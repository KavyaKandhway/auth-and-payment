

import (
	"time"
	"gopkg.in/mgo.v2/bson"
)

//Transaction STruct for handling transactions
type Transaction struct {
	ID           bson.ObjectId `json:"_id,omitempty" bson:"_id,omitempty"`
	userID       bson.ObjectId `json:"userid" bson:"userid"`
	Amount       int           `json:"amount" bson:"amount"`
	Date         time.Time     `json:"date" bson:"date"`
	RZPOrderID   string        `json:"rzporderid" bson:"rzporderid"`
	RZPPaymentID string        `json:"rzppaymentid" bson:"rzppaymentid"`
	Refunds      []Refund      `json:"refunds" bson:"refunds"`
	RecieptID    string        `json:"recieptid" bson:"recieptid"`
}

//Refund struct for recording multiple refunds in the same Transacton
type Refund struct {
	RZPRefundID  string `json:"rzprefundid" bson:"rzprefundid"`
	RefundAmount int    `json:"refundamount" bson:"refundamount"`
}

//InitiateTransaction method calculates the cart and takes care of creating an order with Razorpay
func (t *Transaction) InitiateTransaction(data forms.PrepareTransactionCommand) (transaction Transaction, err error) {
	var userModel = new(User)
	collection := dbConnect.Use("cdb", "trasactions")

	deid := helpers.DecodeIDBase64(data.UserEnID)
	amount := userModel.TransactionAmount(data.UserEnID)

	receiptID := data.UserEnID // random date time
	receiptID += time.Now().String()
	random := helpers.RandomStringGenerator()
	receiptID += random

	rzpbody, err := rzpConnect.CreateOrder(amount, receiptID)
	if err == nil {
		err = collection.Insert(bson.M{
			"userid":     deid,
			"amount":     amount,
			"date":       time.Now(),
			"rzporderid": rzpbody["id"],
			"recieptid":  receiptID,
		})
		_ = collection.Find(bson.M{"userid": deid}).One(&transaction)
		return transaction, nil
	}
	return transaction, err
}

//
func (t *Transaction) GetTransactionByUserID(enid string) (transaction Transaction, err error) {
	// Connect to the transaction collection
	collection := dbConnect.Use("cdb", "transactions")

	// Decode the userID
	deid := helpers.DecodeIDBase64(enid)
	// Assign result to error object while saving user
	err = collection.Find(bson.M{"_id": deid}).One(&transaction)
	return transaction, err
}

//
func (t *Transaction) AddRZPPaymentID(data forms.CaptureTrasactionCommand) (transaction Transaction, err error) { //This is essentially an update, if the data is already  present
	//Connect to the transaction collection
	collection := dbConnect.Use("cdb", "transactions")

	//Initialize filter
	filter := bson.M{}

	deid := helpers.DecodeIDBase64(data.UserEnID)
	filter = bson.M{"_id": deid}
	transaction, _ = t.GetTransactionByUserID(data.UserEnID)

	update := bson.D{
		{"$set", bson.M{
			"rzppaymentid": data.RZPpaymentID,
		}},
	}

	//Assign result to error object while saving phone numbuser, er
	err = collection.Update(filter, update)

	if err == nil {
		transaction.RZPPaymentID = data.RZPpaymentID
	}
	return transaction, err
}

//
func (t *Transaction) InitiateRefund(data forms.RefundTransactionCommand) (transaction Transaction, err error) {
	//Connect to the transaction collection
	collection := dbConnect.Use("cdb", "transactions")

	deid := helpers.DecodeIDBase64(data.UserEnID)
	filter := bson.M{"_id": deid}
	transaction, _ = t.GetTransactionByUserID(data.UserEnID)

	rzpbody, err := rzpConnect.Refund(data.RefundAmount, transaction.RZPPaymentID)

	if err == nil {
		rzpRefundID := rzpbody["id"]
		rzpRefundAmount := rzpbody["amount"]
		err = collection.Insert(bson.M{
			"rzprefundid":  rzpRefundID,
			"refundamount": rzpRefundAmount,
		})

		update := bson.D{
			{
				"$push", bson.M{
					"refunds": bson.M{
						"rzprefundid":  rzpRefundID,
						"refundamount": rzpRefundAmount,
					},
				}},
		}
		err = collection.Update(filter, update)

		var refund Refund
		refund.RZPRefundID = rzpRefundID.(string)
		refund.RefundAmount = rzpRefundAmount.(int)
		if err == nil {
			transaction.Refunds = append(transaction.Refunds, refund)
		}

	}
	return transaction, err
}
