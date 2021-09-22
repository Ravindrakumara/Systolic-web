package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	auth "web_app/middleware"
	models "web_app/models"
	"web_app/utils"

	"github.com/go-chi/render"
	_ "github.com/lib/pq"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
	. "github.com/volatiletech/sqlboiler/v4/queries/qm"
)

var ctx context.Context

var db *sql.DB

func init() {
	query := url.Values{}
	query.Add("database", os.Getenv("database_name"))
	dns := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(os.Getenv("database_user"), os.Getenv("database_password")),
		Host:     fmt.Sprintf("%s:%s", os.Getenv("database_ip"), os.Getenv("database_port")),
		RawQuery: query.Encode(),
	}
	postgresconfig := dns.String()
	ctx = context.Background()
	var err error
	db, err = sql.Open("postgres", postgresconfig)
	if err != nil {
		print(err.Error())
	}
	boil.DebugMode = true
	// SetMaxIdleConns sets the maximum number of connections in the idle connection pool.
	db.SetMaxIdleConns(25)

	// SetMaxOpenConns sets the maximum number of open connections to the database.
	db.SetMaxOpenConns(25)

	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	db.SetConnMaxLifetime(5 * time.Minute)
}

type LoginData struct {
	Userid   string `json:"Userid"`
	Password string `json:"Password"`
}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	var result string
	var login LoginData
	result = "failed"
	json.NewDecoder(r.Body).Decode(&login)
	if (login.Password) != "" && (login.Userid) != "" {
		var loginuser models.MastUser
		models.MastUsers(Select(models.MastUserColumns.UserName, models.MastUserColumns.LoginID, models.MastUserColumns.PasswordHash), models.MastUserWhere.LoginID.EQ(login.Userid)).Bind(ctx, db, &loginuser)
		validuser, _ := utils.ComparePassword(login.Password, loginuser.PasswordHash)
		if validuser {
			tokenstring := auth.EncodeJWT(login.Userid)
			expiration := time.Now().Add(24 * time.Hour)
			cookie := http.Cookie{Name: "jwt", Value: tokenstring, Expires: expiration, HttpOnly: true}
			http.SetCookie(w, &cookie)
			result = "success"
			log.Println(fmt.Sprintf("DEBUG: token:%s username:%s password:%s", tokenstring, login.Userid, login.Password))
		} else {
			result = "failed"
			expiration := time.Now()
			cookie := http.Cookie{Name: "jwt", Value: "", Expires: expiration, HttpOnly: true}
			http.SetCookie(w, &cookie)
			log.Println(fmt.Sprintf("DEBUG: login failed username:%s password:%s", login.Userid, login.Password))
		}
	}
	render.JSON(w, r, result)
}

type StringResult struct {
	Result string `boil:"result"`
}

func UserLogout(w http.ResponseWriter, r *http.Request) {
	expiration := time.Now()
	cookie := http.Cookie{Name: "jwt", Value: "", Expires: expiration, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func UserName(w http.ResponseWriter, r *http.Request) {
	var user models.MastUser
	userid := auth.DecodeJWT(r).(string)
	models.MastUsers(Select(models.MastUserColumns.UserName), models.MastUserWhere.LoginID.EQ(userid)).Bind(ctx, db, &user)
	render.JSON(w, r, user.UserName)
}

func UserCode(w http.ResponseWriter, r *http.Request) {
	var user models.MastUser
	userid := auth.DecodeJWT(r).(string)
	models.MastUsers(Select(models.MastUserColumns.UserCode), models.MastUserWhere.LoginID.EQ(userid)).Bind(ctx, db, &user)
	render.JSON(w, r, user.UserCode)
}

func GetDepartmentCode(w http.ResponseWriter, r *http.Request) {
	var user models.MastUser
	userid := auth.DecodeJWT(r).(string)
	models.MastUsers(Select(models.MastUserColumns.DepartmentCode), models.MastUserWhere.LoginID.EQ(userid)).Bind(ctx, db, &user)
	render.JSON(w, r, user.DepartmentCode)
}

func UserPrivilages(w http.ResponseWriter, r *http.Request) {
	userid := auth.DecodeJWT(r).(string)
	var result StringResult
	var user models.MastUser
	models.MastUsers(Select(models.MastUserColumns.UserCode), models.MastUserWhere.LoginID.EQ(userid)).Bind(ctx, db, &user)
	queries.Raw(`SELECT get_security_rights($1,$2) AS result;`, strings.TrimSpace(user.UserCode), "MAST").Bind(ctx, db, &result)
	render.JSON(w, r, result.Result)
}

func RetrieveUsers(w http.ResponseWriter, r *http.Request) {
	var result StringResult
	queries.Raw(`SELECT retrieve_users() AS result;`).Bind(ctx, db, &result)
	render.PlainText(w, r, result.Result)
}
