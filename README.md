# starttls-scanner

## Setup
1. Install `go` and `postgres`. You can specify the following environment variables:
2.
```
go get github.com/EFForg/starttls-scanner
cd $GOPATH/github.com/EFForg/starttls-scanner
`cp .env.example .env`
```
3. Edit `.env` with your postgres credentials and any other changes to the default configuration. You can also store this in the environment.
4. Ensure `postgres` is running, then run `db/scripts/init_db.sql` in the appropriate postgres DB in order to initialize your database.

Then, you can run:
```
go build
./starttls-scanner
```
to start serving requests at `PORT`.

### Via Docker
```
cp .env.example .env
docker-compose build
docker-compose up
```

## Testing
```
# Service tests
go test -v

# Database tests
go test ./db -v
```
