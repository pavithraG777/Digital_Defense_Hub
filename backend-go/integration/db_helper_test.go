package integration

import (
    "context"
    "os"
    "testing"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

func getTestDatabasePool(t *testing.T) *pgxpool.Pool {
    t.Helper()

    dsn := os.Getenv("TEST_DATABASE_URL")
    if dsn == "" {
        dsn = "postgres://ddh:ddh@localhost:5433/ddh_test?sslmode=disable"
    }

    var pool *pgxpool.Pool
    var err error
    ctx := context.Background()
    for i := 0; i < 10; i++ {
        pool, err = pgxpool.New(ctx, dsn)
        if err == nil {
            if err = pool.Ping(ctx); err == nil {
                return pool
            }
            pool.Close()
        }
        time.Sleep(1 * time.Second)
    }

    t.Skipf("skipping integration test; cannot connect to test db: %v", err)
    return nil
}
