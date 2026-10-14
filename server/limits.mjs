// Upper bound for chats in one grant or Local AI scope. LINE allows up to 5,000
// friends plus every joined group, so the old 1,000 cap rejected real accounts.
// Kept well under SQLite's 32,766 bound-parameter limit used by scoped queries.
export const MAX_SCOPE_CHATS=10000;

// The local dashboard posts whole chat lists (a scope update sends both the new
// and the current list). LINE IDs are 33 characters, so 32 KB failed at about
// 450 chats. Two lists at the cap stay far below this size.
export const ADMIN_JSON_LIMIT='2mb';

// One JSON line on the private worker pipe. A 10 MiB file is about 14 MB as
// base64; this leaves room for metadata without allowing unbounded lines.
export const WORKER_LINE_MAX=16_000_000;

// Gateway request bodies. A file sent inline as base64 needs the same headroom.
// Authentication runs before the body is parsed.
export const GATEWAY_JSON_LIMIT='16mb';
