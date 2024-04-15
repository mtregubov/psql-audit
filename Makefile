build:
	@go build -o psql-audit main.go

run: build
	./psql-audit -d 0.0.0.0:5432 -l 0.0.0.0:2345
