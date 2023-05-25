package jssdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ArtisanCloud/PowerLibs/v3/object"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/basicService/jssdk"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/kernel"
	response2 "github.com/ArtisanCloud/PowerWeChat/v3/src/kernel/response"
)

type Client struct {
	*jssdk.Client
}

func NewClient(app *kernel.ApplicationInterface) (*Client, error) {
	jssdkClient, err := jssdk.NewClient(app)
	if err != nil {
		return nil, err
	}
	client := &Client{
		jssdkClient,
	}

	config := (*app).GetConfig()
	baseURI := config.GetString("http.base_uri", "/")

	client.TicketEndpoint = baseURI + "/cgi-bin/get_jsapi_ticket"

	return client, nil
}

func (comp *Client) GetAppID() string {
	config := (*comp.BaseClient.App).GetConfig()
	return config.GetString("corp_id", "")
}

func (comp *Client) GetAgentConfigArray() {

}

func (comp *Client) ConfigSignature(ctx context.Context, url string, nonce string, timestamp int64) (*object.HashMap, error) {

	if nonce == "" {
		nonce = object.QuickRandom(10)
	}
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}

	result, err := comp.GetTicket(ctx, false, "jsapi")
	if err != nil {
		return result, err
	}
	ticket := (*result)["ticket"].(string)

	return &object.HashMap{
		"appId":     comp.GetAppID(),
		"nonceStr":  nonce,
		"timestamp": timestamp,
		"url":       url,
		"signature": comp.GetTicketSignature(ticket, nonce, timestamp, url),
	}, nil

}

func (comp *Client) GetTicket(ctx context.Context, refresh bool, ticketType string) (*object.HashMap, error) {

	cacheKey := fmt.Sprintf("powerwechat.basic_service.jssdk.ticket.%s.%s", ticketType, comp.GetAppID())

	if !refresh && comp.GetCache().Has(cacheKey) {
		ticket, err := comp.GetCache().Get(cacheKey, nil)
		ticket2 := ticket.(map[string]interface{})
		return (*object.HashMap)(&ticket2), err
	}

	mapRSBody := &object.HashMap{}
	rs, err := comp.BaseClient.RequestRaw(ctx, comp.TicketEndpoint, http.MethodPost, &object.HashMap{
		"query": &object.StringMap{
			"type": ticketType,
		}}, nil, nil)
	if err != nil {
		return nil, err
	}

	err = comp.BaseClient.HttpHelper.ParseResponseBodyToMap(rs, mapRSBody)
	if (*mapRSBody)["errcode"].(float64) != 0 {
		return mapRSBody, errors.New((*mapRSBody)["errmsg"].(string))
	}

	result, err := comp.BaseClient.CastResponseToType(rs, response2.TYPE_MAP)
	if err != nil {
		return nil, err
	}

	resultData := result.(*object.HashMap)
	err = comp.GetCache().Set(cacheKey, result, time.Duration((*resultData)["expires_in"].(float64)-500)*time.Second)
	if err != nil {
		return nil, err
	}

	if !comp.GetCache().Has(cacheKey) {
		return nil, errors.New("Failed to cache jssdk ticket. ")
	}

	return resultData, nil
}
