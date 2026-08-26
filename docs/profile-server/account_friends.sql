-- Friend list storage (account-level, bidirectional)
-- Each row = one direction of a friendship. A<->B has 2 rows.

CREATE TABLE IF NOT EXISTS account_friends (
    accid_owner  INT UNSIGNED NOT NULL,
    accid_target INT UNSIGNED NOT NULL,
    nickname     VARCHAR(15) NOT NULL DEFAULT '',
    PRIMARY KEY (accid_owner, accid_target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
