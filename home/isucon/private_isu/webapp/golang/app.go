package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db        *sqlx.DB
	store     *gsm.MemcacheStore
	userCache sync.Map // map[int]User
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int       `db:"comment_count"`
	Comments     []Comment
	User         User
	CSRFToken    string
	ImageURL     string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetOutput(io.Discard)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
		"UPDATE posts SET comment_count = 0",
		"UPDATE posts p JOIN (SELECT post_id, COUNT(*) AS cnt FROM comments GROUP BY post_id) c ON p.id = c.post_id SET p.comment_count = c.cnt",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT `id`, `account_name`, `passhash` FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

var (
	accountNameRegex = regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`)
	passwordRegex    = regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`)
)

func validateUser(accountName, password string) bool {
	return accountNameRegex.MatchString(accountName) && passwordRegex.MatchString(password)
}

func digest(src string) string {
	h := sha512.Sum512([]byte(src))
	return hex.EncodeToString(h[:])
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	var idInt int
	switch v := uid.(type) {
	case int:
		idInt = v
	case int64:
		idInt = int(v)
	default:
		return User{}
	}

	if cached, ok := userCache.Load(idInt); ok {
		return cached.(User)
	}

	u := User{}
	err := db.Get(&u, "SELECT `id`, `account_name`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `id` = ?", idInt)
	if err != nil {
		return User{}
	}

	userCache.Store(idInt, u)
	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

// loadUsersInto は ids のうち userMap にまだ無いものを userCache から先に引き、
// そこにも無い分だけまとめて 1 度だけ DB に問い合わせる。
// 取得結果は userCache に格納して以後のリクエストに再利用させる。
func loadUsersInto(ids []int, userMap map[int]User) error {
	var missing []int
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if _, ok := userMap[id]; ok {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if v, ok := userCache.Load(id); ok {
			userMap[id] = v.(User)
			continue
		}
		missing = append(missing, id)
	}
	if len(missing) == 0 {
		return nil
	}
	query, args, err := sqlx.In("SELECT `id`, `account_name`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `id` IN (?)", missing)
	if err != nil {
		return err
	}
	var us []User
	if err := db.Select(&us, query, args...); err != nil {
		return err
	}
	for _, u := range us {
		userMap[u.ID] = u
		userCache.Store(u.ID, u)
	}
	return nil
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	postUserIDs := make([]int, 0, len(results))
	seen := make(map[int]bool, len(results))
	for _, result := range results {
		if _, ok := seen[result.UserID]; ok {
			continue
		}
		postUserIDs = append(postUserIDs, result.UserID)
		seen[result.UserID] = true
	}

	userMap := make(map[int]User, len(postUserIDs))
	if err := loadUsersInto(postUserIDs, userMap); err != nil {
		return nil, err
	}

	posts := make([]Post, 0, postsPerPage)
	// posts に出ていく id 全部 (extraIDs での dedup や reverse 用)
	postIDs := make([]int, 0, postsPerPage)
	// comment_count > 0 の post だけ comments 取得対象に入れる。
	// 0 件 post を IN から除けば scan 範囲・転送 row 数が減る。
	commentingIDs := make([]int, 0, postsPerPage)
	for _, p := range results {
		u, ok := userMap[p.UserID]
		if !ok || u.DelFlg != 0 {
			continue
		}
		p.User = u
		p.CSRFToken = csrfToken
		p.ImageURL = imageURL(p)
		posts = append(posts, p)
		postIDs = append(postIDs, p.ID)
		if p.CommentCount > 0 {
			commentingIDs = append(commentingIDs, p.ID)
		}
		if len(posts) >= postsPerPage {
			break
		}
	}
	if len(posts) == 0 {
		return posts, nil
	}

	var comments []Comment
	if len(commentingIDs) > 0 {
		// idx_post_created (post_id, created_at) に乗る covering scan。
		// 直近 3 件への絞り込みは MySQL の ROW_NUMBER OVER PARTITION より
		// Go 側で post_id 毎にカウントする方が安い (temp table を作らない)。
		query, args, err := sqlx.In("SELECT `id`, `post_id`, `user_id`, `comment`, `created_at` FROM `comments` WHERE `post_id` IN (?) ORDER BY `post_id`, `created_at` DESC", commentingIDs)
		if err != nil {
			return nil, err
		}
		if err := db.Select(&comments, query, args...); err != nil {
			return nil, err
		}
		if !allComments {
			out := comments[:0]
			countByPost := make(map[int]int, len(commentingIDs))
			for _, c := range comments {
				if countByPost[c.PostID] >= 3 {
					continue
				}
				countByPost[c.PostID]++
				out = append(out, c)
			}
			comments = out
		}
	}

	extraIDs := make([]int, 0)
	for _, c := range comments {
		if _, ok := userMap[c.UserID]; !ok {
			extraIDs = append(extraIDs, c.UserID)
		}
	}
	if len(extraIDs) > 0 {
		if err := loadUsersInto(extraIDs, userMap); err != nil {
			return nil, err
		}
	}

	commentsByPost := make(map[int][]Comment, len(posts))
	for _, c := range comments {
		c.User = userMap[c.UserID]
		commentsByPost[c.PostID] = append(commentsByPost[c.PostID], c)
	}
	for i := range posts {
		cs := commentsByPost[posts[i].ID]
		for l, r := 0, len(cs)-1; l < r; l, r = l+1, r-1 {
			cs[l], cs[r] = cs[r], cs[l]
		}
		posts[i].Comments = cs
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

var (
	loginTpl = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html"),
	))
	registerTpl = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html"),
	))
	indexTpl = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("index.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
	accountTpl = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
	postsTpl = template.Must(template.ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	))
	postIDTpl = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	))
	bannedTpl = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html"),
	))
)

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	userCache = sync.Map{}

	// 初期 1000 ユーザーを cache に流し込んで cold-start の IN クエリ嵐を回避する。
	// ベンチ中に追加された新規 user は makePosts/getSessionUser 経由で随時育つ。
	var users []User
	if err := db.Select(&users, "SELECT `id`, `account_name`, `authority`, `del_flg`, `created_at` FROM `users`"); err == nil {
		for _, u := range users {
			userCache.Store(u.ID, u)
		}
	}

	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	loginTpl.Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	registerTpl.Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	// JOIN users で del_flg=0 を絞ると users 駆動の filesort になる
	// (EXPLAIN で 11k 行 temporary)。idx_posts_created_at の reverse scan
	// が効くよう JOIN を外し、makePosts 側で del_flg!=0 を弾く。
	// 弾かれる前提で多めに over-fetch する。
	err := db.Select(&results, `
SELECT id, user_id, body, mime, created_at, comment_count
FROM posts
ORDER BY created_at DESC
LIMIT ?
`, postsPerPage*3)
	if err != nil {
		log.Print(err)
		return
	}

	csrfToken := getCSRFToken(r)
	posts, err := makePosts(results, csrfToken, false)
	if err != nil {
		log.Print(err)
		return
	}

	indexTpl.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, csrfToken, getFlash(w, r, "notice")})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := r.PathValue("accountName")
	user := User{}

	err := db.Get(&user, "SELECT `id`, `account_name`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at`, `comment_count` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT ?", user.ID, postsPerPage)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	type counts struct {
		CommentCount   int `db:"comment_count"`
		PostCount      int `db:"post_count"`
		CommentedCount int `db:"commented_count"`
	}

	var c counts
	err = db.Get(&c, `
SELECT (SELECT COUNT(*) FROM comments WHERE user_id = ?) AS comment_count,
       (SELECT COUNT(*) FROM posts WHERE user_id = ?)    AS post_count,
       (SELECT COUNT(*)
        FROM comments c
                 JOIN posts p ON c.post_id = p.id
        WHERE p.user_id = ?)                             AS commented_count
`, user.ID, user.ID, user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	me := getSessionUser(r)

	accountTpl.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, c.PostCount, c.CommentCount, c.CommentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	// getIndex と同じ理由で JOIN を外して idx_posts_created_at に乗せる。
	err = db.Select(&results, `
SELECT id, user_id, body, mime, created_at, comment_count
FROM posts
WHERE created_at <= ?
ORDER BY created_at DESC LIMIT ?
`, t.Format(ISO8601Format), postsPerPage*3)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	postsTpl.Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.PathValue("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at`, `comment_count` FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	postIDTpl.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	ext := map[string]string{
		"image/jpeg": "jpg",
		"image/png":  "png",
		"image/gif":  "gif",
	}[mime]
	if ext != "" {
		imgFilePath := fmt.Sprintf("/home/isucon/private_isu/webapp/public/image/%d.%s", pid, ext)
		_ = os.WriteFile(imgFilePath, filedata, 0644)
	}

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	tx, err := db.Beginx()
	if err != nil {
		log.Print(err)
		return
	}
	if _, err := tx.Exec("INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)", postID, me.ID, r.FormValue("comment")); err != nil {
		tx.Rollback()
		log.Print(err)
		return
	}
	if _, err := tx.Exec("UPDATE `posts` SET `comment_count` = `comment_count` + 1 WHERE `id` = ?", postID); err != nil {
		tx.Rollback()
		log.Print(err)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Print(err)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT `id`, `account_name`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	bannedTpl.Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
		if idInt, err := strconv.Atoi(id); err == nil {
			userCache.Delete(idInt)
		}
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := "3307"
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(100)
	db.SetConnMaxLifetime(3 * time.Minute)
	defer db.Close()

	root, err := os.OpenRoot("../public")
	if err != nil {
		log.Fatalf("failed to open root: %v", err)
	}
	defer root.Close()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServerFS(root.FS()).ServeHTTP(w, r)
	})

	go func() {
		log.Println(http.ListenAndServe("127.0.0.1:6060", nil))
	}()

	log.Fatal(http.ListenAndServe(":8080", r))
}
