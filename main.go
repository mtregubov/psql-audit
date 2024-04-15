package main

import (
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/jeroenrinzema/psql-wire/pkg/buffer"
)

var listening = flag.String("l", "0.0.0.0:6432", "port the psql-audit is listening on")
var dial = flag.String("d", "0.0.0.0:5432", "PostgreSQL server target")
var tls = flag.Bool("tls", false, "this flag has to be set whenever the server is supporting TLS connections")
var logger *slog.Logger

func main() {
	flag.Parse()
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

	err := run()
	if err != nil {
		slog.Error("unexpected error", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	listener, err := net.Listen("tcp", *listening)
	if err != nil {
		return err
	}

	logger.Info("psql-audit listening", slog.String("address", *listening))

	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}

		logger.Info("incoming connection, dialing PostgreSQL server...")

		db, err := net.Dial("tcp", *dial)
		if err != nil {
			return err
		}

		go sniffer(client, db)
	}
}

func sniffer(client, db net.Conn) {

	ip := string(client.RemoteAddr().String())
	app := ""
	user := ""
	to := io.TeeReader(client, db)
	from := io.TeeReader(db, client)

	logger.Info("starting sniffing the PSQL protocol")

	go func() {
		reader := buffer.NewReader(slog.Default(), to, 0)
		_, err := reader.ReadUntypedMsg()
		if err != nil {
			logger.Error("unexpected error while reading the client version", slog.String("err", err.Error()))
			return
		}

		version, _ := reader.GetUint32()
		logger.Info("client to server", slog.Uint64("version", uint64(version)))

		if !*tls {
			// NOTE: we have to read a untyped message twice if TLS is disabled (check handshake)
			reader.ReadUntypedMsg()
		}

		for {
			t, _, err := reader.ReadTypedMsg()
			if err == io.EOF {
				return
			}

			if err != nil {
				logger.Error("unexpected error while reading a typed client message", slog.String("err", err.Error()))
				return
			}

			cmd := strings.ToLower(string(reader.Msg))
			cmd = strings.Replace(cmd, "\u0000", "", -1)
			skip := false
			if strings.Contains(cmd, "pg_catalog") {
				skip = true
			}
			//if string(t) == "Q" && strings.Contains(cmd, "select") && !skip {
			if string(t) == "Q" && !skip {
				logger.Info("client to server", "ip", ip, "app", app, "user", user, "type", string(t), "msg", cmd)
			}
		}
	}()

	go func() {
		if !*tls {
			bb := make([]byte, 1)
			_, err := from.Read(bb)
			if err != nil {
				logger.Error("unexpected error while reading the tls response", slog.String("err", err.Error()))
				return
			}
		}

		reader := buffer.NewReader(slog.Default(), from, 0)
		for {
			t, _, err := reader.ReadTypedMsg()
			if err == io.EOF {
				return
			}

			if err != nil {
				logger.Error("unexpected error while reading the server response", slog.String("err", err.Error()))
				return
			}
			resp := strings.ToLower(string(reader.Msg))
			if string(t) == "S" && strings.Contains(resp, "application_name") {
				app = extractapp(resp)
			}
			if string(t) == "S" && strings.Contains(resp, "session_authorization") {
				user = extractuser(resp)
			}
			if string(t) == "E" {
				logger.Error("server to client", "ip", ip, "msg", strings.Replace(string(reader.Msg), "\u0000", " ", -1))
			}
		}
	}()
}

func extractapp(s string) string {
	l := strings.Split(s, "\x00")
	if len(l) < 2 {
		logger.Warn("unable to extract application name, set it to default", "str", s)
		return "psql"
	}
	return l[1]
}

func extractuser(s string) string {
	l := strings.Split(s, "\x00")
	if len(l) < 2 {
		logger.Warn("unable to extract username name, set it to default", "str", s)
		return "uknown"
	}
	return l[1]
}
