package main

import b64 "encoding/base64"


import (

	"net/http"
	"fmt"
	"log"
	"github.com/gorilla/mux"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"encoding/json"
	"encoding/hex"

	"time"
	"bytes"
	"io/ioutil"
	"github.com/jamesruan/sodium"
)

var db *mgo.Database
const(USERS_COLLECTION = "users")
const(LOGGING_COLLECTION = "logging")
const(ETHEREUM_NODE_SERVER = "http://13.124.246.189:8545/")


//const MongoDb details
const (
	hosts      = "13.124.246.189:27017"
	database   = "admin"
	username   = "root"
	password   = "skeeter"
	collection = "users"
)


type PostResponse struct {
	Status        string `json:"status"`
	Message  	string `json:"message"`
	Code 		int   `json:"code"`
}

type Keys struct{
	Secretkey 	string `bson:"secretkey" json:"secretkey"`
	PublicKey 	string `bson:"publicKey" json:"publicKey"`
}



type User struct{

	ID     			bson.ObjectId `json:"_id" bson:"_id"`
	UserName        string `bson:"userName" json"userName"`
	BrowserPrint  	string `bson:"browserPrint" json:"browserPrint"`
	UserKeys 		Keys   `bson:"keys" json:"keys"`
}

type EthereumPostData struct{
	Jsonrpc string `bson:"jsonrpc" json"jsonrpc"`
	Method 	string `bson:"method" json"method"`
	Params []EthereumPostDataParams `bson:"params" json"params"`
	Id string `bson:"id" json"id"`

}
type EthereumPostDataParams struct{
	From string `bson:"from" json"from"`
	To string `bson:"to" json"to"`
	Datea string `bson:"data" json"data"`
}


type Logging struct{
	UserName string `bson:"userName" json"userName"`
	BroswerPrint string `bson:"browserPrint" json"browserprint"`
	Action string `bson:"action" json"action"`
	BlockchainId string `bson:"blockchainId" json"blockchainId"`
}


type RPCResponse struct{
	Jsonrpc string `bson:"jsonrpc" json"jsonrpc"`
	Id string `bson:"id" json"id"`
	Result string `bson:"result" json"result"`

}


func PoscoUpdateUserEndPoint(w http.ResponseWriter, r *http.Request){

	user := User{}

	err := json.NewDecoder(r.Body).Decode(&user)
	if (err != nil) {
		w.Write([]byte("JSON Parsing Error"))
	}

	fmt.Println("input object: ", user)


	// create the keypair
	keypair := sodium.MakeBoxKP()

	// convert sercret key to base64
	sk, err := json.Marshal(keypair.SecretKey)
	if err != nil{
		fmt.Println("error:", err)
	}

	encodedSecretKey := b64.StdEncoding.EncodeToString(sk)


	// convert public key to base64
	pk, err := json.Marshal(keypair.PublicKey)
	if err != nil {
		fmt.Println("error:", err)
	}

	encodedPublickKey := b64.StdEncoding.EncodeToString(pk)

	fmt.Println("SecretKey ", encodedSecretKey)
	fmt.Println("PublickKey ", encodedPublickKey)


	user.UserKeys = Keys{PublicKey:encodedPublickKey, Secretkey:encodedSecretKey}

	fmt.Println("user object created ", user)

	info := &mgo.DialInfo{
		Addrs:    []string{hosts},
		Timeout:  60 * time.Second,
		Database: database,
		Username: username,
		Password: password,
	}

	session, err1 := mgo.DialWithInfo(info)
	if err1 != nil {
		panic(err1)
	}

	defer session.Close()

	//error check on every access
	session.SetSafe(&mgo.Safe{})

	user.ID = bson.NewObjectId()

	c := session.DB("posco").C("users")
	err = c.Insert(user)
	if err != nil {
		panic(err)
	}


	out, err := json.Marshal(user)
	encodedStr := hex.EncodeToString([]byte(string(out)))
	fmt.Println("clear data to be stored in blockchain", (string(out)))
	fmt.Println("hex data to be stored in blockchain", "0x"+encodedStr)

	params := EthereumPostDataParams{"0xa2051505226eb0f0986912d7e822bbed9294ac6b", "0xa2051505226eb0f0986912d7e822bbed9294ac6b", encodedStr}
	postData := EthereumPostData{"2.0", "eth_sendTransaction", []EthereumPostDataParams{params}, "99"}

	fmt.Println("Ethereum Post Data ", postData)

	jsonValue, _ := json.Marshal(postData)
	request_eth, _ := http.NewRequest("POST", ETHEREUM_NODE_SERVER, bytes.NewBuffer(jsonValue))
	request_eth.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response_eth, err := client.Do(request_eth)
	if err != nil {
		fmt.Printf("The HTTP request failed with error %s\n", err)
	} else {
		data, _ := ioutil.ReadAll(response_eth.Body)
		fmt.Println(string(data))

		rpcResponse := new(RPCResponse)
		json.Unmarshal(data, &rpcResponse)

		loggingData := Logging{
			UserName:     user.UserName,
			BroswerPrint: user.BrowserPrint,
			Action:       "create-user",
			BlockchainId: rpcResponse.Result,
		}

		// insert logging record in to mongodb
		c := session.DB("posco").C("logging")
		err = c.Insert(loggingData)
		if err != nil {
			panic(err)
		}

		// user found but no browser print does not match
		response := PostResponse{"success", "user updated", 0}
		b, err2 := json.Marshal(response);
		if err2 == nil {
			w.Write(b)
		}
		return;
	}

}
func PoscoLoginEndPoint(w http.ResponseWriter,  r *http.Request) {

	user := User{}

	err := json.NewDecoder(r.Body).Decode(&user)
	if (err != nil) {
		w.Write([]byte("JSON Parsing Error"))
	}

	fmt.Println("input object: ", user)
	//userJSON, err := json.u(user)

	info := &mgo.DialInfo{
		Addrs:    []string{hosts},
		Timeout:  60 * time.Second,
		Database: database,
		Username: username,
		Password: password,
	}

	session, err1 := mgo.DialWithInfo(info)
	if err1 != nil {
		panic(err1)
	}

	defer session.Close()

	//error check on every access
	session.SetSafe(&mgo.Safe{})

	var results []User
	err = session.DB("posco").C("users").Find(bson.M{"userName": user.UserName}).All(&results)
	if err != nil {
		fmt.Printf("find fail %v\n", err)

		response := PostResponse{"FAILURE", "DB Error", -1}
		b, err2 := json.Marshal(response);
		if err2 == nil {
			w.Write(b)
		}

	} else {

		// this user is not found
		if results == nil {
			response := PostResponse{"success", "User Not Found", 2}
			b, err2 := json.Marshal(response);
			if err2 == nil {
				w.Write(b)
			}

		} else {

			// check for the browser print
			for _, res := range results {

				// browser print found
				if res.BrowserPrint == user.BrowserPrint {

					response := PostResponse{"success", "Fingerprint Found", 0}
					b, err2 := json.Marshal(response);
					if err2 == nil {
						w.Write(b)
					}

					out, err := json.Marshal(res)
					if err != nil {
						panic(err)
					}

					encodedStr := hex.EncodeToString([]byte(string(out)))
					fmt.Println("clear data to be stored in blockchain", (string(out)))
					fmt.Println("hex data to be stored in blockchain", "0x"+encodedStr)

					params := EthereumPostDataParams{"0xa2051505226eb0f0986912d7e822bbed9294ac6b", "0xa2051505226eb0f0986912d7e822bbed9294ac6b", encodedStr}
					postData := EthereumPostData{"2.0", "eth_sendTransaction", []EthereumPostDataParams{params}, "99"}

					fmt.Println("Ethereum Post Data ", postData)

					jsonValue, _ := json.Marshal(postData)
					request_eth, _ := http.NewRequest("POST", ETHEREUM_NODE_SERVER, bytes.NewBuffer(jsonValue))
					request_eth.Header.Set("Content-Type", "application/json")
					client := &http.Client{}
					response_eth, err := client.Do(request_eth)
					if err != nil {
						fmt.Printf("The HTTP request failed with error %s\n", err)
					} else {
						data, _ := ioutil.ReadAll(response_eth.Body)
						fmt.Println(string(data))

						rpcResponse := new(RPCResponse)
						json.Unmarshal(data, &rpcResponse)

						loggingData := Logging{
							UserName:     res.UserName,
							BroswerPrint: res.BrowserPrint,
							Action:       "validate",
							BlockchainId: rpcResponse.Result,
						}

						// insert logging record in to mongodb
						c := session.DB("posco").C("logging")
						err = c.Insert(loggingData)
						if err != nil {
							panic(err)
						}

					}

					return;
				}

			}

			// user found but no browser print does not match
			response := PostResponse{"success", "Fingerprint Not Found", 1}
			b, err2 := json.Marshal(response);
			if err2 == nil {
				w.Write(b)
			}

			out, err := json.Marshal(user)
			encodedStr := hex.EncodeToString([]byte(string(out)))
			fmt.Println("clear data to be stored in blockchain", (string(out)))
			fmt.Println("hex data to be stored in blockchain", "0x"+encodedStr)

			params := EthereumPostDataParams{"0xa2051505226eb0f0986912d7e822bbed9294ac6b", "0xa2051505226eb0f0986912d7e822bbed9294ac6b", encodedStr}
			postData := EthereumPostData{"2.0", "eth_sendTransaction", []EthereumPostDataParams{params}, "99"}

			fmt.Println("Ethereum Post Data ", postData)

			jsonValue, _ := json.Marshal(postData)
			request_eth, _ := http.NewRequest("POST", ETHEREUM_NODE_SERVER, bytes.NewBuffer(jsonValue))
			request_eth.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			response_eth, err := client.Do(request_eth)
			if err != nil {
				fmt.Printf("The HTTP request failed with error %s\n", err)
			} else {
				data, _ := ioutil.ReadAll(response_eth.Body)
				fmt.Println(string(data))

				rpcResponse := new(RPCResponse)
				json.Unmarshal(data, &rpcResponse)

				loggingData := Logging{
					UserName:     user.UserName,
					BroswerPrint: user.BrowserPrint,
					Action:       "not-validate",
					BlockchainId: rpcResponse.Result,
				}

				// insert logging record in to mongodb
				c := session.DB("posco").C("logging")
				err = c.Insert(loggingData)
				if err != nil {
					panic(err)
				}

				return;
			}
		}
	}
}


func main() {
	r := mux.NewRouter();

	r.HandleFunc("/PoscoLogin", PoscoLoginEndPoint).Methods("POST")
	r.HandleFunc("/updateUser", PoscoUpdateUserEndPoint).Methods("POST")
	if err := http.ListenAndServe(":3000", r); err != nil {
		log.Fatal(err)
	}
}
