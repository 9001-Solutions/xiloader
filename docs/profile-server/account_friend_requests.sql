-- Pending friend requests (cleaned up on accept/decline)

CREATE TABLE IF NOT EXISTS account_friend_requests (
    accid_from    INT UNSIGNED NOT NULL,
    accid_to      INT UNSIGNED NOT NULL,
    nickname      VARCHAR(15) NOT NULL DEFAULT '',
    charname_from VARCHAR(15) NOT NULL DEFAULT '',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (accid_from, accid_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
