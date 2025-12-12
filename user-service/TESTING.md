# Testing in `user-service`

This document describes the current testing setup for the `user-service` module and the main flows covered by the tests.

---

## 1. Test Layers

We use several kinds of tests:

### 1.1 Integration tests (`@SpringBootTest`)

- **Purpose:** Verify full flows end-to-end: HTTP → security → service → DB → JSON response.
- **Example:** `UserControllerIntegrationTest`
- **Characteristics:**
    - Start the full Spring context.
    - Use `MockMvc` to call real controller endpoints.
    - Use real repositories (`UserProfileRepository`, `RoleRepository`, `EmailVerificationTokenRepository`).
    - Use real `PasswordEncoder`, security configuration and JWT generation.
    - Run with `@ActiveProfiles("test")` using `application-test.yml`.
    - `@Transactional` and `@DirtiesContext` to isolate tests.

### 1.2 Web MVC / security tests (`@WebMvcTest`)

- **Purpose:** Focus on controller layer & security without the full application stack.
- **Examples:**
    - `UserControllerMvcTest` – request/response mapping, validation, error handling.
    - `UserControllerSecurityTest` – access control (401/403) for different roles.
- **Characteristics:**
    - Use `@WebMvcTest` + `MockMvc`.
    - Mock dependencies such as services or custom security beans.
    - Do **not** hit the real database.

### 1.3 Unit tests (services, utilities)

- **Purpose:** Test business logic without Spring.
- **Examples:** (not listed here explicitly)
    - Service logic.
    - JWT / utility classes.
    - Validators, mappers, small helper components.
- **Characteristics:**
    - Plain JUnit 5 tests, no Spring context.
    - Very fast, focused on one class at a time.

---

## 2. `UserControllerIntegrationTest`

This is the main integration test class that exercises the REST API and database together.

**Annotations & setup:**

- `@SpringBootTest`
- `@AutoConfigureMockMvc`
- `@ActiveProfiles("test")`
- `@Transactional`
- `@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)`

**Injected beans:**

- `MockMvc`
- `UserProfileRepository`
- `RoleRepository`
- `PasswordEncoder`
- `EmailVerificationTokenRepository`
- `ObjectMapper`

**Test data setup:**

- `@BeforeEach` loads `ADMIN` and `USER` roles from the DB (seeded by `DataLoader`).
- Helper `createUser(...)` creates enabled users with specific roles and encoded passwords.
- Helper `loginAndGetToken(...)` performs `/users/login` and extracts the JWT from `LoginResponseDTO`.

### 2.1 Signup (`POST /users/signup`)

Covers:

- **Happy path:**
    - `signup_createsUser_andIsAccessibleWithoutAuthentication`
        - Anonymous signup is allowed.
        - User is created with encoded password and `USER` role.
        - `Location` header points to `/users/signup/{id}`.

- **Duplicate email:**
    - `signup_withExistingEmail_returnsBadRequestAndErrorBody`
        - When email already exists, returns `400 Bad Request` with error body:
            - `{"email": "Email already exists"}`

### 2.2 Login (`POST /users/login`)

Covers:

- **Valid credentials:**
    - `login_withValidCredentials_returnsTokenAndUserDto`
        - Returns HTTP 200.
        - Response body:
            - `token` – non-empty JWT string.
            - `user` – object containing `id`, `email`, `roles`.

- **Invalid credentials:**
    - `login_withInvalidCredentials_returns401`
        - Returns 401 with error body:
            - `{"auth": "invalid email or password"}`

### 2.3 Current user (`GET /users/me`)

- `getCurrentUser_returnsProfileOfAuthenticatedUser`
    - Authenticated user retrieves their own profile.
    - Asserts `id` and `email` match the logged-in user.

### 2.4 List users (`GET /users` – admin only)

Covers access control:

- `getUsers_unauthenticated_returns401`
    - No auth → 401.

- `getUsers_authenticatedAsUser_returns403`
    - Regular `USER` role → 403, error `"Insufficient privileges"`.

- `getUsers_authenticatedAsAdmin_returns200_andListsUsers` (`@Tag("smoke")`)
    - `ADMIN` role → 200.
    - Response has `X-Total-Count` header.
    - Response array contains user entries with `email`.

### 2.5 Get user by ID (`GET /users/{id}`)

PreAuthorize: `#id == principal.id or hasRole('ADMIN')`

- **Owner access:**
    - `getUser_asOwner_returns200` (`@Tag("smoke")`)
        - Owner can fetch their own user.

- **Different user:**
    - `getUser_asDifferentUser_returns403`
        - Another regular user gets 403 + `"Insufficient privileges"`.

- **Admin access:**
    - `getUser_asAdmin_canAccessAnyUser_returns200`
        - Admin can fetch any user by ID.

### 2.6 Update user (`PATCH /users/{id}`)

Same PreAuthorize rule.

- **Unauthenticated:**
    - `patchUser_unauthenticated_returns401`
        - No auth → 401.

- **Different user:**
    - `patchUser_asDifferentUser_returns403_andDoesNotChangeData`
        - 403 + error body.
        - Asserts DB data not changed.

- **Owner updates own name:**
    - `patchUser_asOwner_updatesOwnName_returns200`
        - Owner can change their `name`.
        - Email remains unchanged.

- **Admin updates any user’s name:**
    - `patchUser_asAdmin_canUpdateAnyUserName_returns200`
        - Admin updates another user’s name.
        - Asserts DB change.

### 2.7 Change email (`PATCH /users/{id}/email`)

Flow includes re-authentication and disabling the user.

- **Correct password + JWT:**
    - `changeEmail_withCorrectPassword_changesEmailAndDisablesUser`
        - Setup: user is created via `createUser`.
        - `loginAndGetToken` gets JWT for this user.
        - PATCH with `Authorization: Bearer <token>` and correct `currentPassword`:
            - Returns 204 No Content.
            - In DB:
                - `email` updated.
                - `enabled` set to `false`.

- **Wrong password:**
    - `changeEmail_withWrongPassword_returnsUnauthorizedOrBadCredentials`
        - Wrong `currentPassword`.
        - Returns 401 (or other error depending on handler).
        - Email unchanged, `enabled` remains `true`.

### 2.8 Change password (`PATCH /users/{id}/password`)

- **Owner + correct old password:**
    - `changePassword_asOwner_withCorrectOldPassword_updatesPassword`
        - Returns 204.
        - Stored hash matches new password.

- **Owner + wrong old password:**
    - `changePassword_asOwner_withWrongOldPassword_returnsBadRequest`
        - Returns 400.
        - Error: `{"password": "Credentials are wrong"}`.

- **Different user:**
    - `changePassword_asDifferentUser_returnsForbidden`
        - 403 with `"Insufficient privileges"`.

### 2.9 Delete user (`DELETE /users/{id}`)

PreAuthorize: `#id == principal.id or hasRole('ADMIN')`

- `deleteUser_unauthenticated_returns401`
    - No auth → 401.

- `deleteUser_asDifferentUser_returns403_andDoesNotDelete`
    - 403 + error body.
    - DB still contains the user.

- `deleteUser_asOwner_deletesOwnAccount_returns204`
    - Owner can delete themselves.
    - DB no longer contains the user.

- `deleteUser_asAdmin_canDeleteAnyUser_returns204`
    - Admin can delete any user.

### 2.10 Email verification (`GET /auth/verify-email`)

Signup initially creates a **disabled** user and a verification token.

- `signup_createsDisabledUser_andVerificationToken`
    - After signup:
        - User exists with `enabled = false`.
        - Exactly one `EmailVerificationToken` exists for that user.
        - Token is not used and expires in the future.

- `verifyEmail_enablesUser_andMarksTokenUsed`
    - After calling `/auth/verify-email?token=...`:
        - User becomes `enabled = true`.
        - Token is marked `used = true`.

- `verifyEmail_withInvalidToken_returnsBadRequest`
    - Non-existing / invalid token.
    - Returns 400 with `"Invalid or expired verification link"`.

### 2.11 Full flow 1: signup → verify email → get/patch own profile

- `userFlow_signup_verifyEmail_thenGetAndPatchOwnProfileName`
    - Steps:
        1. `POST /users/signup` → user disabled + verification token created.
        2. `GET /auth/verify-email?token=...` → user enabled.
        3. `GET /users/{id}` as the same user → 200 with correct data.
        4. `PATCH /users/{id}` to change `name`.
        5. `GET /users/{id}` again to confirm updated `name`.

    - Uses `httpBasic` authentication for the flow after verification.

### 2.12 Full flow 2: admin manages user by ID

- `adminFlow_getThenDeleteUser_thenSubsequentGetFails`
    - Steps:
        1. Create admin + regular user.
        2. `loginAndGetToken` for admin, obtain JWT.
        3. `GET /users/{id}` with `Authorization: Bearer <adminToken>` → 200.
        4. `DELETE /users/{id}` with `Authorization: Bearer <adminToken>` → 204.
        5. `GET /users/{id}` again:
            - User no longer exists.
            - Returns 404 with `"User not found"`.

---

## 3. Helper Methods

### 3.1 `createUser(String email, String rawPassword, Role... roles)`

- Encodes the raw password using `PasswordEncoder`.
- Creates an enabled, non-locked `UserProfile` with given roles.
- Persists it via `UserProfileRepository`.
- Used in many tests to quickly set up users with specific roles and credentials.

### 3.2 `loginAndGetToken(String email, String password)`

- Sends `POST /users/login` with the given credentials.
- Expects 200 OK.
- Deserializes response into `LoginResponseDTO`.
- Returns `resp.getToken()` – used to build `Authorization: Bearer <token>` headers in tests that need JWT auth.

---

## 4. Tags

Some tests are marked with JUnit 5 tags:

- `@Tag("smoke")` – a small subset of important “sanity” tests:
    - `signup_createsUser_andIsAccessibleWithoutAuthentication`
    - `getUsers_authenticatedAsAdmin_returns200_andListsUsers`
    - `getUser_asOwner_returns200`

You can configure your build tool (Gradle/Maven) to include or exclude these tags for fast smoke runs.

---

## 5. Adding New Tests

When adding new tests:

1. Decide the level:
    - Pure business logic? → **Unit test** in a service/utility test class.
    - Controller mapping / validation / 401/403 checks? → **Web MVC / security test**.
    - Full flow touching DB and security? → **Integration test** (e.g. extend `UserControllerIntegrationTest` or create a similar class).

2. Follow naming conventions:
    - Use descriptive names:  
      `methodOrFlow_context_expectedResult`, for example:
        - `resendVerificationEmail_forDisabledUser_createsNewToken`
        - `refreshToken_withExpiredAccessToken_returnsNewAccessToken`

3. Reuse helpers:
    - Use `createUser(...)` for initial data.
    - Use `loginAndGetToken(...)` whenever you need a valid JWT.

4. Keep flows grouped:
    - Add new tests next to related ones (e.g. all email flows together, all password flows together).
    - Optionally use `@Nested` classes if flows become large and you want more structure.

---
