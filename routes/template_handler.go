package routes

import (
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"math/rand"
	"fmt"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/markbates/pkger"
)

type TemplateHandler struct {
	config *models.Config
}

var config models.Config
var templates *template.Template
var assets map[string]string

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func NewTemplateHandler(config *models.Config) *TemplateHandler {
	assets = make(map[string]string)
	return &TemplateHandler{config: config}
}

func (g *TemplateHandler) HandleEmbeddedTemplate(response http.ResponseWriter, request *http.Request) {
	// Ensure browsers will always use HTTPS, unless running only locally (dev/test mode)
	if (g.config.Host == "127.0.0.1" || g.config.Host == "localhost") &&
		(request.Header.Get(g.config.OriginalProtoHeader) == "https" || g.config.SSLMode != "off") {
		response.Header().Set("Strict-Transport-Security", "max-age=31536000; preload")
	}
	fileName := strings.Trim(request.URL.Path, "/")
	if fileName == "" {
		fileName = "index"
	}

	g.config.NonceCode = RandStringBytes(32)
	fmt.Println(g.config.NonceCode)
	err := templates.ExecuteTemplate(response, fileName, g.config)
	if err != nil {
		log.Printf("Error serving template %s: %s", fileName, err.Error())
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (g *TemplateHandler) HandleStaticAsset(response http.ResponseWriter, request *http.Request) {
	fileName := request.URL.Path
	if content, exists := assets[fileName]; exists == true {
		// Send proper content-type for JS as this is required for the service worker
		if strings.HasSuffix(fileName, ".js") {
			response.Header().Set("Content-Type", "text/javascript")
		} else if strings.HasSuffix(fileName, ".css") {
			response.Header().Set("Content-Type", "text/css")
		}
		response.Write([]byte(content))
	} else {
		http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}

}

func (g *TemplateHandler) CompileTemplates(dir string) error {
	const fun = "compileTemplates"
	tpl := template.New("")
	// Since Walk receives a dynamic value, pkger won't be able to find the
	// actual directory to package from the next line, which is why we used
	// pkger.Include() in routes.go.
	err := pkger.Walk(dir, func(path string, info os.FileInfo, _ error) error {
		// Skip non-templates.
		if info.IsDir() {
			return nil
		}
		// Load file from pkpger virtual file, or real file if pkged.go has not
		// yet been generated, during development.
		f, _ := pkger.Open(path)
		// Now read it.
		sl, _ := ioutil.ReadAll(f)
		// It can now be parsed as a string.
		tpl.Parse(string(sl))
		return nil
	})
	loadStaticAssets(dir)
	templates = tpl
	return err
}

func loadStaticAssets(dir string) error {
	err := pkger.Walk(dir, func(path string, info os.FileInfo, _ error) error {
		// Skip non-assets.
		if info.IsDir() || (!strings.Contains(path, "/service.js") && !strings.Contains(path, "/assets/") && !strings.Contains(path, "/fonts/")) {
			return nil
		}
		// Load file from pkpger virtual file, or real file if pkged.go has not
		// yet been generated, during development.
		f, _ := pkger.Open(path)
		// Now read it.
		sl, _ := ioutil.ReadAll(f)
		filePath := strings.Split(path, ":")[1]
		assetPath := strings.TrimPrefix(filePath, "/templates")
		assets[assetPath] = string(sl)
		return nil
	})
	return err
}
