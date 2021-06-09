package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/twinj/uuid"
)

const SENDGRID_API_KEY = ""

var accessSecretKey []byte = []byte("access_secret")
var refreshSecretKey []byte = []byte("refresh_secret")
var linkSecretKey []byte = []byte("link_secret")
var key []byte
var jwtSecretKey = []byte("jwt_secret_key")

type User struct {
	ID    uint64 `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

type LoginParams struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type AccessParams struct {
	AccessT string `json:"accesst"`
}

type ErrorResponse struct {
	Code    int
	Message string
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
	LinkToken    string
	LinkUuid     string
	LtExpires    int64
}

type SuccessfulLoginResponse struct {
	Email        string
	RefreshToken string
	AccessToken  string
}

type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

type Claims struct {
	Email string
	jwt.StandardClaims
}

type Message struct {
	Name string
	Text string
}

var Usermap = map[string]bool{}
var linkAccess = map[string]string{}

func main() {

	log.Println("Server will start at http://localhost:8000/")

	//ConnectDatabase()

	route := mux.NewRouter()

	AddApproutes(route)

	log.Fatal(http.ListenAndServe(":8000", route))
}

func AddApproutes(route *mux.Router) {

	log.Println("Loadeding Routes...")

	route.HandleFunc("/", RenderHome)

	route.HandleFunc("/signup", ExtractToken)
	route.HandleFunc("/food", Food).Methods("POST")

	route.HandleFunc("/login", RenderLogin).Methods("POST")
	route.HandleFunc("/logout", RenderLogout).Methods("POST")
	route.HandleFunc("/fire", FirebaseSet).Methods("POST")

	log.Println("Routes are Loaded.")
}
func FirebaseSet(response http.ResponseWriter, request *http.Request) {
	var FirebaseRequest AccessParams
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Its not you its me",
	}
	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&logoutRequest)
	defer request.Body.Close()
	if decoderErr != nil {
		returnErrorResponse(response, request, errorResponse)
	} else {
		errorResponse.Code = http.StatusBadRequest
		log.Println(logoutRequest.AccessT)
		if logoutRequest.AccessT == "" {
			errorResponse.Message = "Token cant be empty"
			returnErrorResponse(response, request, errorResponse)
		} else {
			app, err := firebase.NewApp(context.Background(), nil)
			if err != nil {
				log.Fatalf("error initializing app: %v\n", err)
			} else {
				verifyIDToken(ctx, app, token)
			}

		}
}
func verifyIDToken(ctx context.Context, app *firebase.App, idToken string) *auth.Token {
	// [START verify_id_token_golang]
	client, err := app.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	token, err := client.VerifyIDToken(ctx, idToken)
	if err != nil {
		log.Fatalf("error verifying ID token: %v\n", err)
	}

	log.Printf("Verified ID token: %v\n", token)

	return token
}
func RenderHome(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	response.Write([]byte(`{"message": "Unauthorized access"}`))
}

func RenderLogout(response http.ResponseWriter, request *http.Request) {
	var logoutRequest AccessParams
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Its not you its me",
	}
	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&logoutRequest)
	defer request.Body.Close()
	if decoderErr != nil {
		returnErrorResponse(response, request, errorResponse)
	} else {
		errorResponse.Code = http.StatusBadRequest
		log.Println(logoutRequest.AccessT)
		if logoutRequest.AccessT == "" {
			errorResponse.Message = "Token cant be empty"
			returnErrorResponse(response, request, errorResponse)
		} else {
			// var Usermap = map[string]bool{}
			// var linkAccess
			var tokenVerification bool = VerifyToken(logoutRequest.AccessT, accessSecretKey)
			if tokenVerification == false {
				errorResponse.Code = http.StatusBadRequest
				errorResponse.Message = "Invalid token sent"
				returnErrorResponse(response, request, errorResponse)
			} else {
				delete(Usermap, linkAccess[logoutRequest.AccessT])
				delete(linkAccess, logoutRequest.AccessT)
				var successResponse = SuccessResponse{
					Code:    http.StatusOK,
					Message: "Logged out, Verify your email again to login",
				}

				successJSONResponse, jsonError := json.Marshal(successResponse)

				if jsonError != nil {
					returnErrorResponse(response, request, errorResponse)
				}
				response.Header().Set("Content-Type", "application/json")
				response.Write(successJSONResponse)
			}

		}
	}
}
func Food(response http.ResponseWriter, request *http.Request) {
	var foodRequest AccessParams
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "Its not you its me",
	}
	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&foodRequest)
	defer request.Body.Close()
	if decoderErr != nil {
		returnErrorResponse(response, request, errorResponse)
	} else {
		errorResponse.Code = http.StatusBadRequest
		log.Println(foodRequest.AccessT)
		if foodRequest.AccessT == "" {
			errorResponse.Message = "Token cant be empty"
			returnErrorResponse(response, request, errorResponse)
		} else {
			var tokenVerification bool = VerifyToken(foodRequest.AccessT, accessSecretKey)
			if tokenVerification == false {
				errorResponse.Code = http.StatusBadRequest
				errorResponse.Message = "Invalid token sent"
				returnErrorResponse(response, request, errorResponse)
			} else if Usermap[linkAccess[foodRequest.AccessT]] == false {
				errorResponse.Code = http.StatusBadRequest
				errorResponse.Message = "Email link not verified"
				returnErrorResponse(response, request, errorResponse)
			} else {
				var successResponse = SuccessResponse{
					Code:    http.StatusOK,
					Message: "Successfully verified",
				}

				successJSONResponse, jsonError := json.Marshal(successResponse)

				if jsonError != nil {
					returnErrorResponse(response, request, errorResponse)
				}
				response.Header().Set("Content-Type", "application/json")
				response.Write(successJSONResponse)
			}
		}
	}

}

func RenderLogin(response http.ResponseWriter, request *http.Request) {
	var loginRequest LoginParams
	var errorResponse = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "It's not you it's me.",
	}
	decoder := json.NewDecoder(request.Body)
	decoderErr := decoder.Decode(&loginRequest)
	defer request.Body.Close()

	if decoderErr != nil {
		returnErrorResponse(response, request, errorResponse)
	} else {
		errorResponse.Code = http.StatusBadRequest
		if loginRequest.Email == "" {
			errorResponse.Message = "Email Name can't be empty"
			returnErrorResponse(response, request, errorResponse)
		} else if loginRequest.Name == "" {
			errorResponse.Message = "Name can't be empty"
			returnErrorResponse(response, request, errorResponse)
		} else {

			tokenString, _ := CreateJWT(loginRequest)

			if tokenString == nil {
				returnErrorResponse(response, request, errorResponse)
			}
			linkAccess[tokenString.AccessToken] = tokenString.LinkToken
			log.Println(tokenString.LinkToken)
			var successResponse = SuccessResponse{
				Code:    http.StatusOK,
				Message: "You are registered, check mail to authenticate",
				Response: SuccessfulLoginResponse{
					RefreshToken: tokenString.RefreshToken,
					AccessToken:  tokenString.AccessToken,
					Email:        loginRequest.Email,
				},
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				returnErrorResponse(response, request, errorResponse)
			}
			response.Header().Set("Content-Type", "application/json")
			response.Write(successJSONResponse)

			link := CreateMagicLink(*tokenString)
			Usermap[tokenString.AccessToken] = false
			//SendMail(link, loginRequest)
			log.Println(link)
		}
	}
}

func returnErrorResponse(response http.ResponseWriter, request *http.Request, errorMesage ErrorResponse) {
	httpResponse := &ErrorResponse{Code: errorMesage.Code, Message: errorMesage.Message}
	jsonResponse, err := json.Marshal(httpResponse)
	if err != nil {
		panic(err)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(errorMesage.Code)
	response.Write(jsonResponse)
}

func CreateJWT(loginab LoginParams) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()
	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()
	td.LtExpires = time.Now().Add(time.Minute * 10).Unix()
	var err error
	//Creating Access Token
	key = []byte(os.Getenv("SECRET_KEY"))
	os.Setenv("ACCESS_SECRET", "") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["email"] = loginab.Email
	atClaims["name"] = loginab.Name
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "") 
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	//Creating Link Token
	os.Setenv("REFRESH_SECRET", "") 
	ltClaims := jwt.MapClaims{}
	ltClaims["link_uuid"] = td.LinkUuid
	ltClaims["exp"] = td.LtExpires
	lt := jwt.NewWithClaims(jwt.SigningMethodHS256, ltClaims)
	td.LinkToken, err = lt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func CreateMagicLink(tokenab TokenDetails) string {
	var link string
	link = "http://localhost:8000" + "/signup" + "?token=" + tokenab.LinkToken
	return link
}
func SendMail(link string, loginRequest LoginParams) {
	from := mail.NewEmail("Example User", "test@xyz.com")
	subject := "Link Verificationn"
	to := mail.NewEmail("Example User", loginRequest.Email)
	plainTextContent := "Link---" + link
	htmlContent := "link " + link
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(SENDGRID_API_KEY)
	response, err := client.Send(message)
	if err != nil {
		log.Println(err)
	} else {
		log.Println(response.StatusCode)
		log.Println(response.Body)
		log.Println(response.Headers)
	}
}

func ExtractToken(response http.ResponseWriter, request *http.Request) {
	bearToken := request.FormValue("token")
	//normally Authorization the_token_xxx
	log.Println(bearToken)
	var successResponse = SuccessResponse{
		Code:    http.StatusOK,
		Message: bearToken,
	}
	var errorResponse ErrorResponse
	successJSONResponse, jsonError := json.Marshal(successResponse)
	if jsonError != nil {
		returnErrorResponse(response, request, errorResponse)
	}
	response.Header().Set("Content-Type", "application/json")
	response.Write(successJSONResponse)
	if VerifyToken(bearToken, linkSecretKey) == true {
		Usermap[bearToken] = true
	} else {
		Usermap[bearToken] = false
	}
}

func VerifyToken(tokenString string, secretKey []byte) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")

		return secretKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("verified")
		fmt.Println(claims["foo"], claims["nbf"])
		return true
	} else {
		fmt.Println(err)
		return false
	}

}
