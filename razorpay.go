

import (
	"os"

	razorpay "github.com/razorpay/razorpay-go"
)

//RazorpayClient is a struct for handling a payment client
type RazorpayClient struct {
	client *razorpay.Client
}

//NewSession initiates a new razorpay session
func NewRZPSession() (rzp *RazorpayClient) {
	rzpclient := razorpay.NewClient(os.Getenv("RZPY_API_KEY"), os.Getenv("RZPY_API_SECRET"))
	rzp = &RazorpayClient{rzpclient}
	return rzp
}

//CreateOrder creates a new order before the user makes the payment. Its a helper function
//which should be called by a controller
func (rzp *RazorpayClient) CreateOrder(amount int, receiptid string) (rzpbody map[string]interface{}, err error) {
	data := map[string]interface{}{
		"amount":   amount * 100, //Razorpay accepts the value in paisa hence a multiplier of 100
		"currency": "INR",
		"receipt":  receiptid,
	}
	rzpbody, err = rzp.client.Order.Create(data, nil)
	return rzpbody, err
}

//Refund method creates refunds for the end user
func (rzp *RazorpayClient) Refund(amount int, rzppaymentid string) (rzpbody map[string]interface{}, err error) {
	rzpbody, err = rzp.client.Payment.Refund(rzppaymentid, amount*100, nil, nil)
	return rzpbody, err
}

//


