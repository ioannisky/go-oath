package otp

import "testing"
//import "github.com/ioannisky/go-oath/otp"


func checkOTP(t *testing.T, o OTP,a map[int]string, desc string) {
	//fmt.Printf("Checking %s\n",desc)
	for key, val := range a {
		o.Offset=key
		ret := o.GetKey()
		var exp string
		if(ret==val) {
			exp="True"
		}else {
			exp="False"
			t.Fail()			
		}
		
		t.Logf("%d %s %s %s\n",o.Offset,ret,val,exp)
		//fmt.Printf("%d %s %s %s\n",o.Offset,ret,val,exp)
	}

}


func TestOTP(t *testing.T) {
	checksSHA1 := map[int]string{0:"755224", 1:"287082", 2:"359152", 3:"969429", 4:"338314", 5:"254676", 6:"287922", 7:"162583", 8:"399871", 9:"520489"}
	checksSHA1T := map[int]string{59:"94287082", 1111111109:"07081804", 1111111111:"14050471", 1234567890:"89005924", 2000000000:"69279037", 20000000000:"65353130"}
	checksSHA256T := map[int]string{59:"46119246", 1111111109:"68084774", 1111111111:"67062674", 1234567890:"91819424", 2000000000:"90698825", 20000000000:"77737706"}
	checksSHA512T := map[int]string{59:"90693936", 1111111109:"25091201", 1111111111:"99943326", 1234567890:"93441116", 2000000000:"38618901", 20000000000:"47863826"}

	var o OTP
	o.Key="12345678901234567890"
	o.Algorithm="sha1"
	o.Offset=0
	o.Digits=6
	o.TimeDiv=1
	o.AlignKey=true

	checkOTP(t,o,checksSHA1,"SHA1")

	o.Digits=8
	o.Algorithm="sha1"
	o.TimeDiv=30

	checkOTP(t,o,checksSHA1T,"SHA1T")

	o.Algorithm="sha256"
	checkOTP(t,o,checksSHA256T,"SHA256T")
	
	o.Algorithm="sha512"
	checkOTP(t,o,checksSHA512T,"SHA512T")

}


