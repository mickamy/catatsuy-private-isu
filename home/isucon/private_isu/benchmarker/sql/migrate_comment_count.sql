-- posts.comment_count を非正規化カラムとして追加し、既存データを backfill する
ALTER TABLE posts ADD COLUMN comment_count INT NOT NULL DEFAULT 0;
UPDATE posts p
JOIN (
    SELECT post_id, COUNT(*) AS cnt FROM comments GROUP BY post_id
) c ON p.id = c.post_id
SET p.comment_count = c.cnt;
