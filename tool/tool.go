package tool

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
	"strconv"
)

func ReadInt(data []byte) (int, error) {
	var i int32
	ndata := make([]byte, 4)
	if len(data) <= 4 {
		copy(ndata[4-len(data):], data)
	}
	if len(data) > 4 {
		copy(ndata, data[len(data)-4:])
	}
	buf := bytes.NewBuffer(ndata)
	err := binary.Read(buf, binary.BigEndian, &i)
	return int(i), err
}

func WriteInt(i int16) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, i)
	if err != nil {
		return nil, err
	}
	if len(buf.Bytes()) == 2 {
		return buf.Bytes(), err
	}
	return nil, errors.New("Bytes length is not 2")
}

func GetTimeCookie()string{
	now := time.Now()
	year,mon,day := now.UTC().Date()
	hour := now.UTC().Hour()
	return strconv.Itoa(year)+mon.String()+strconv.Itoa(day)+strconv.Itoa(hour)
}
