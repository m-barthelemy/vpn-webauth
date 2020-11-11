package routes

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/m-barthelemy/vpn-webauth/models"
)

type TemplateHandler struct {
	config *models.Config
}

var config models.Config

func NewTemplateHandler(config *models.Config) *TemplateHandler {
	return &TemplateHandler{config: config}
}

func (g *TemplateHandler) HandleTemplate(response http.ResponseWriter, request *http.Request) {
	fileName := strings.Trim(request.URL.Path, "/")
	if fileName == "" {
		fileName = "index.html"
	}
	tmplt := template.New(fileName)
	tmplt, _ = tmplt.ParseFiles("templates/" + fileName)

	if err := tmplt.Execute(response, g.config); err != nil {
		log.Println(err.Error())
		http.Error(response, http.StatusText(500), 500)
	}

}
