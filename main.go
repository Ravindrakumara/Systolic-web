package main

import (
	"fmt"
	"net/http"
	"os"
	controllers "web_app/controllers"
	auth "web_app/middleware"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"github.com/go-chi/render"

	"github.com/go-chi/cors"
)

func main() {
	r := chi.NewRouter()
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{os.Getenv("consumer_origin")},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Access-Control-Allow-Credentials", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	r.Use(middleware.RequestID)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	//r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(auth.EncodeJWT("Hi")))
	})

	r.Route("/api", func(r chi.Router) {

		r.Group(func(r chi.Router) {
			r.Get("/login", controllers.UserLogin)
			r.Post("/login", controllers.UserLogin)
			r.Get("/logout", controllers.UserLogout)
			r.Post("/logout", controllers.UserLogout)
		})

		r.Group(func(r chi.Router) {

			r.Use(jwtauth.Verifier(auth.Jwt.TokenAuth))

			r.Use(jwtauth.Authenticator)

			r.Get("/verify", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(fmt.Sprintf("hi %s", auth.DecodeJWT(r))))
			})

			r.Get("/securityprivilages", controllers.UserPrivilages)

			r.Get("/username", controllers.UserName)
			r.Get("/usercode", controllers.UserCode)
			r.Get("/users", controllers.RetrieveUsers)

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(fmt.Sprintf("%s", auth.DecodeJWT(r))))
			})
		})

	})

	http.ListenAndServe(":"+os.Getenv("webapp_port"), r)
}
