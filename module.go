package auth

import (
	"github.com/gin-gonic/gin"
)

var registeredModules = make(map[string]Module)

// Moduler should be implemented by all the authboss modules.
type Module func(auth *Engine) gin.HandlerFunc

// RegisterModule with the core providing all the necessary information to
// integrate into authboss.
func RegisterModule(name string, m Module) {
	registeredModules[name] = m
}

// RegisteredModules returns a list of modules that are currently registered.
func RegisteredModules() []string {
	mods := make([]string, len(registeredModules))
	i := 0
	for k := range registeredModules {
		mods[i] = k
		i++
	}

	return mods
}

// LoadedModules returns a list of modules that are currently loaded.
func (a *Engine) LoadedModules() []string {
	mods := make([]string, len(registeredModules))
	i := 0
	for k := range registeredModules {
		mods[i] = k
		i++
	}

	return mods
}

// IsLoaded checks if a specific module is loaded.
func (a *Engine) IsLoaded(mod string) bool {
	_, ok := registeredModules[mod]
	return ok
}

// ModuleListMiddleware puts a map in the data that can be used
// to provide the renderer with information about which pieces of the
// views to show. The bool is extraneous, as presence in the map is
// the indication of wether or not the module is loaded.
// Data looks like:
// map[modulename] = true
//
// oauth2 providers are also listed here using the syntax:
// oauth2.google for an example. Be careful since this doesn't actually mean
// that the oauth2 module has been loaded so you should do a conditional
// that checks for both.
// func ModuleListMiddleware(ab *Engine) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var data HTMLData

// 			ctx := r.Context()
// 			dataIntf := ctx.Value(CTXKeyData)
// 			if dataIntf != nil {
// 				data = dataIntf.(HTMLData)
// 			} else {
// 				data = HTMLData{}
// 			}

// 			loaded := make(map[string]bool, len(ab.loadedModules))
// 			for k := range ab.loadedModules {
// 				loaded[k] = true
// 			}

// 			for provider := range ab.Config.Modules.OAuth2Providers {
// 				loaded["oauth2."+provider] = true
// 			}

// 			data[DataModules] = loaded
// 			r = r.WithContext(context.WithValue(ctx, CTXKeyData, data))
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }
