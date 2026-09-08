-- Friend messaging (offline mailbox)
-- Messages persist until explicitly deleted.
-- msg_type matches FFXiMain's canonical icon-type table (table at +0x383088,
-- mirrored in friend.cpp:get_icon_label):
--   0  = NRM (regular)
--   1  = FWT (incoming friend request)
--   3  = KNK
--   9  = FOK (friend accepted)
--   10 = FNO (friend declined)
--   anything else -> OTR (default fallthrough)

CREATE TABLE IF NOT EXISTS account_friend_messages (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_accid  INT UNSIGNED NOT NULL,
    to_accid    INT UNSIGNED NOT NULL,
    msg_type    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    subject     VARCHAR(64)  NOT NULL DEFAULT '',
    body        VARCHAR(512) NOT NULL DEFAULT '',
    is_read     TINYINT(1)   NOT NULL DEFAULT 0,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_to_unread (to_accid, is_read, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
