package main

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"firebase.google.com/go/v4/auth/hash"
	"golang.org/x/sync/errgroup"
	firebaseclientopt "google.golang.org/api/option"
)

func main() {
	if err := run(os.Args, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	ctx := context.Background()

	app, err := firebase.NewApp(ctx, nil, firebaseclientopt.WithCredentialsFile("./justwatch-auth-dev-8-firebase.json"))
	if err != nil {
		return err
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return err
	}

	batchNumber := 0
	errGroup, groupCtx := errgroup.WithContext(ctx)
	ratelimiter := make(chan struct{}, 32)

	errGroup.Go(func() (err error) {
		for {
			batchNumber++

			var batch []*auth.UserToImport
			for i := 0; i < 1000; i++ {
				uid := randString(8)

				firebaseUser := (&auth.UserToImport{}).
					UID(uid).
					ProviderData([]*auth.UserProvider{
						{
							UID:        uid,
							ProviderID: "google.com",
						},
					})

				batch = append(batch, firebaseUser)
			}

			ratelimiter <- struct{}{}
			fmt.Println("batch", batchNumber, "started")

			errGroup.Go(func() (err error) {
				defer func() { <-ratelimiter }()

				start := time.Now()
				if _, err := client.ImportUsers(groupCtx, batch, auth.WithHash(hash.Bcrypt{})); err != nil {
					return err
				}
				fmt.Println("batch", batchNumber, "done in", time.Since(start))

				return nil
			})
		}
	})

	return errGroup.Wait()
}

var letterRunes = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
