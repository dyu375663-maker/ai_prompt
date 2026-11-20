# Security Specification — 나의 AI 프롬프트 창고

## 1. Data Invariants
- Collection `/prompts/{promptId}` stores public AI prompt templates with exact schema keys: `title`, `category`, `content`, `createdAt`.
- Public read (`get`, `list`) is allowed for guests without login, bounded by `isValidId(promptId)` on `get` and `request.query.limit != null && request.query.limit <= 100` on `list`.
- All write operations (`create`, `update`, `delete`) strictly require `isAdmin()`, verified by `request.auth != null && request.auth.token.email_verified == true && request.auth.token.email == 'dyu375663@gmail.com'`.
- `promptId` must match `^[a-zA-Z0-9_\-]+$` and be at most 128 characters.
- `title` must be a non-empty string (`1..100` chars).
- `category` must be one of the 3 allowed categories: `"사진 합성"`, `"스타일 변환"`, `"캐릭터·포스터"`.
- `content` must be a non-empty string (`1..10000` chars).
- `createdAt` must equal `request.time` on creation and remain immutable on updates.
- All unlisted collections and paths are denied by default (`match /{document=**} { allow read, write: if false; }`).

## 2. Adversarial Payloads ("Dirty Dozen")
1. **Unauthenticated Create**: Guest attempts to create a prompt -> Rejected by `isAdmin()`.
2. **Non-Admin Authenticated Create**: Signed-in non-admin Google user attempts to create/update/delete -> Rejected by `request.auth.token.email == 'dyu375663@gmail.com'`.
3. **Unverified Email Spoof**: Token with admin email string but `email_verified: false` -> Rejected by `request.auth.token.email_verified == true`.
4. **Shadow Field Injection on Create**: Admin payload with extra field `isAdmin: true` -> Rejected by `keys().hasOnly(...)`.
5. **Invalid Category Enum**: `category: "기타"` -> Rejected by category allowlist.
6. **Empty or Oversized Title**: `""` or >100 chars -> Rejected by `title.size()`.
7. **Empty or Oversized Content**: `""` or >10000 chars -> Rejected by `content.size()`.
8. **Forged Client Timestamp**: `createdAt != request.time` -> Rejected on create.
9. **Immutable Field Mutation on Update**: Updating `createdAt` -> Rejected by `affectedKeys().hasOnly(['title', 'category', 'content']) && incoming().createdAt == existing().createdAt`.
10. **ID Poisoning**: Document ID >128 chars or containing invalid characters -> Rejected by `isValidId(promptId)`.
11. **Unbounded List Scraping**: Querying `/prompts` without `limit <= 100` -> Rejected by `request.query.limit != null && request.query.limit <= 100`.
12. **Unlisted Collection Access**: Reading/writing `/users/1` or `/admin/config` -> Rejected by global default-deny catch-all.
