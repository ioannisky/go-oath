package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	//"fmt"
	"math"
	"strconv"
	"hash"
)


type OTP struct {
	Key string
	Offset int
	Algorithm string
	Digits int
	TimeDiv int
	AlignKey bool
}

func uint64tobyte(a uint64) [8]byte {
	var r [8]byte
	r[0]= byte(a >> 56 & 0xff)
	r[1]= byte(a >> 48 & 0xff)
	r[2]= byte(a >> 40 & 0xff)
	r[3]= byte(a >> 32 & 0xff)
	r[4]= byte(a >> 24 & 0xff)
	r[5]= byte(a >> 16 & 0xff)
	r[6]= byte(a >> 8 & 0xff)
	r[7]= byte(a & 0xff)

	return r
}


func (o *OTP) GetKey() string {
	
	var f func() hash.Hash
	var algSize=0
	if (o.Algorithm=="sha1") {
		f = sha1.New
		algSize=sha1.Size
	}else if (o.Algorithm=="sha256") {
		f = sha256.New
		algSize=sha256.Size
	}else if (o.Algorithm=="sha512") {
		f = sha512.New
		algSize=sha512.Size
	}

	
	key := o.Key
	//oKeySize := len(key)
	if(o.AlignKey==true){
		for(len(key)<algSize) {
			key=key+key
		}		
		if(len(key)>algSize) {
			key=key[0:algSize]
		}


	}

	

	h := hmac.New(f,[]byte(key))
	
	oarr := uint64tobyte(uint64(o.Offset/o.TimeDiv))


	h.Write(oarr[:])
	s := h.Sum(nil)

	b := s[len(s)-1] & 0xf
	bi:=int(b)

	var val [4]byte

	val[0] = s[bi] & 0x7f
	val[1] = s[bi+1]
	val[2] = s[bi+2]
	val[3] = s[bi+3]
	
	var i uint32
	
	i=0
	i=i | (uint32(val[0])<<24)
	i=i | (uint32(val[1])<<16)
	i=i | (uint32(val[2])<<8)
	i=i | (uint32(val[3]))

	i2 := int(i)
	
	var tok int

	tok = (i2 % int(math.Pow(10,float64(o.Digits))))

	ret := strconv.Itoa(tok)
	
	for i:=0; i<(o.Digits-len(ret));i++ {
		ret="0"+ret
	}


	return ret
}

