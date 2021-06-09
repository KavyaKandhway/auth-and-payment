
type PrepareTransactionCommand struct {
	UserEnID string `json:"userid" bson:"userid"`
}

type CaptureTrasactionCommand struct {
	UserEnID     string `json:"userid" bson:"userid"`
	RZPorderID   string `json:"rzporderid" bson:"rzporderid"`
	RZPpaymentID string `json:"rzppaymentid" bson:"rzppaymentid"`
}

type RefundTransactionCommand struct {
	UserEnID     string `json:"userid" bson:"userid"`
	RefundAmount int    `json:"refundamount" bson:"refundamount"`
}
