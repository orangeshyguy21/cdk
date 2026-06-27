-- Add per-keyset transaction counters used by the autorotate volume trigger.
ALTER TABLE keyset_amounts ADD COLUMN issued_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE keyset_amounts ADD COLUMN redeemed_count BIGINT NOT NULL DEFAULT 0;

UPDATE keyset_amounts SET issued_count = sub.cnt
FROM (
    SELECT keyset_id, COUNT(*) AS cnt
    FROM blind_signature
    WHERE c IS NOT NULL
    GROUP BY keyset_id
) sub
WHERE keyset_amounts.keyset_id = sub.keyset_id;

UPDATE keyset_amounts SET redeemed_count = sub.cnt
FROM (
    SELECT keyset_id, COUNT(*) AS cnt
    FROM proof
    WHERE state = 'SPENT'
    GROUP BY keyset_id
) sub
WHERE keyset_amounts.keyset_id = sub.keyset_id;
