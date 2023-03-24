package app

import (
	"github.com/gorilla/mux"
	"github.com/kosha/payments-ca-fif/pkg/config"
	"github.com/kosha/payments-ca-fif/pkg/logger"
	"log"
	"net/http"
)

type App struct {
	Router *mux.Router
	Log    logger.Logger
	Cfg    *config.Config
}

func router() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	return router
}

//func commonMiddleware(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		// Do stuff here
//		fmt.Println(r.RequestURI)
//		// Call the next handler, which can be another middleware in the chain, or the final handler.
//		respondWithJSON(w, http.StatusOK, "ok")
//		//next.ServeHTTP(w, r)
//	})
//}

// Initialize creates the necessary scaffolding of the app
func (a *App) Initialize(log logger.Logger) {

	cfg := config.Get()

	a.Cfg = cfg
	a.Log = log

	a.Router = router()
}

// Run starts the app and serves on the specified addr
func (a *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, a.Router))
}
