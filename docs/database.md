# Database

The API runs on **SQLite** (development, tests; the default) or **MySQL 8** (production, like the reference).

| Setting | Meaning |
|---|---|
| `Database__Provider` | `sqlite` (default) or `mysql` |
| `ConnectionStrings__Default` | SQLite: `Data Source=workai360.db`. MySQL: `Server=...;Database=workai360;User=...;Password=...` |
| `Database__AutoMigrate` | MySQL only. Apply pending migrations at startup. Default: on in Development, off elsewhere (the API then refuses to start while migrations are pending) |

Create the MySQL database with a case-insensitive utf8mb4 collation (team names are unique ignoring case, as in the reference):

```sql
CREATE DATABASE workai360 CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
```

## Schema changes

* **SQLite** has no migrations: the schema is created from the model on first start, and tables or nullable columns a newer build added are
  created automatically (`Data/DevSchema.cs`). It never alters or drops anything; delete the file to start over.
* **MySQL** uses EF Core migrations in `src/WorkAI360.Api/Migrations/`. Deploy with a separate step that runs the new build once with
  `--migrate` (it applies migrations and exits), then start the instances with `Database__AutoMigrate=false`. The compose file does exactly this.

Adding or changing an entity:

```bash
dotnet tool install --global dotnet-ef --version "10.*"
cd src/WorkAI360.Api
dotnet build
dotnet ef migrations add <WhatChanged> -o Migrations      # uses Data/DesignTimeFactory.cs: no database needed
dotnet ef migrations has-pending-model-changes            # prints nothing wrong when the model and migrations agree
```

CI fails when an entity changed without a migration (`.github/workflows/ci.yml`, job `migrations`).

## Design rules that keep both databases working

* No provider-specific SQL in features. Use portable constructs: for "at most one active X per Y", keep a nullable column that equals the key
  while active and is empty otherwise, with a plain unique index (see `PermissionSetTeam.ActiveTeamId`). Do not use filtered indexes.
* Every key, foreign-key and indexed text column gets a length on MySQL automatically (255); give other columns explicit lengths when a
  limit matters. Unbounded text is fine for non-indexed columns.
* Case-insensitive uniqueness comes from the collation: SQLite needs `UseCollation("NOCASE")` on the property (done only when the provider is
  SQLite), MySQL's default collation already compares ignoring case.
* Run the test suite on both: `WORKAI_TEST_MYSQL="Server=127.0.0.1;User=root;Password=..." dotnet test` makes every test class use its own
  throwaway MySQL database.
* Under real concurrency MySQL reports conflicts (unique violations, deadlocks) that SQLite hides by serializing writers. Code that can race
  must treat a `DbUpdateException` as "try again against what the winner left" or as a conflict response, never as a 500.
