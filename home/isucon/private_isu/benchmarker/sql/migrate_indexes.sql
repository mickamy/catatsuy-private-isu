-- スロークエリ digest 上位を解消するための index 群。
-- いずれも IF NOT EXISTS 相当で書きたいが MySQL 8 では不可なので、
-- 適用前に SHOW INDEX でチェックするか、エラーを許容して再実行する想定。

-- 1) getAccountName の COUNT(*) 系を埋める
--    SELECT COUNT(*) FROM comments WHERE user_id = ?
ALTER TABLE comments
  ADD INDEX idx_comments_user_id (user_id);

-- 2) getAccountName の posts WHERE user_id = ? ORDER BY created_at DESC
--    posts WHERE user_id = ? の COUNT もこの index に乗る
ALTER TABLE posts
  ADD INDEX idx_posts_user_id_created_at (user_id, created_at);

-- 3) トップページ / getPosts の posts ORDER BY created_at DESC LIMIT
--    JOIN users 後の sort を覆面 index で埋める
ALTER TABLE posts
  ADD INDEX idx_posts_created_at (created_at DESC);

-- comments(post_id, created_at) は idx_post_created として既に存在するため追加しない。
-- makePosts の comments WHERE post_id IN (...) ORDER BY created_at DESC は
-- 既存 idx_post_created で覆われている。
