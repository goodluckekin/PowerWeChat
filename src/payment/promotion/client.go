package promotion

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/ArtisanCloud/PowerLibs/v3/object"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/kernel/power"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/kernel/support"
	payment "github.com/ArtisanCloud/PowerWeChat/v3/src/payment/kernel"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/payment/promotion/request"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/payment/promotion/response"
)

type Client struct {
	*payment.BaseClient
}

func NewClient(app *payment.ApplicationPaymentInterface) (*Client, error) {
	baseClient, err := payment.NewBaseClient(app)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseClient,
	}, nil
}

// 向员工付款
// https://work.weixin.qq.com/api/doc/90000/90135/90278
func (comp *Client) PayTransferToPocket(ctx context.Context, data *request.RequestPayTransferToPocket, appSecret string) (*response.ResponsePayTransferToPocket, error) {
	result := &response.ResponsePayTransferToPocket{}

	//params, err := object.StructToHashMapWithTag(data, "json")
	params, err := object.StructToHashMapWithXML(data)
	if err != nil {
		return nil, err
	}

	endpoint := comp.Wrap("/mmpaymkttransfers/promotion/paywwsptrans2pocket")
	_, err = comp.SafeRequestWork(ctx, endpoint, params, http.MethodPost, &object.HashMap{}, nil, result, appSecret)

	return result, err
}

// 查询付款记录
// https://work.weixin.qq.com/api/doc/90000/90135/90279
func (comp *Client) QueryTransferToPocket(ctx context.Context, data *request.RequestQueryTransferToPocket, appSecret string) (*response.ResponseQueryTransferToPocket, error) {

	result := &response.ResponseQueryTransferToPocket{}

	//params, err := object.StructToHashMapWithTag(data,"json")
	params, err := object.StructToHashMap(data)
	if err != nil {
		return nil, err
	}

	endpoint := comp.Wrap("/mmpaymkttransfers/promotion/querywwsptrans2pocket")
	_, err = comp.SafeRequestWork(ctx, endpoint, params, http.MethodPost, &object.HashMap{}, nil, result, appSecret)

	return result, err
}

func (client *Client) SafeRequestWork(ctx context.Context, url string, params *object.HashMap, method string, option *object.HashMap, outHeader interface{}, outBody interface{}, appSecret string) (interface{}, error) {
	config := (*client.App).GetConfig()

	httpConfig := client.HttpHelper.GetClient().GetConfig()
	httpConfig.Cert.CertFile = config.GetString("cert_path", "")
	httpConfig.Cert.KeyFile = config.GetString("key_path", "")
	client.HttpHelper.GetClient().SetConfig(&httpConfig)

	strOutBody := ""
	// get xml string result from return raw as true
	rs, err := client.RequestV2Work(
		ctx,
		url,
		params,
		method,
		option,
		true,
		outHeader,
		&strOutBody,
		appSecret,
	)

	if err != nil {
		return nil, err
	}

	// get out result
	client.HttpHelper.ParseResponseBodyContent(rs, outBody)

	return outBody, err
}

func (client *Client) RequestV2Work(ctx context.Context, endpoint string, params *object.HashMap, method string, option *object.HashMap,
	returnRaw bool, outHeader interface{}, outBody interface{}, appSecret string,
) (response *http.Response, err error) {

	config := (*client.App).GetConfig()

	base := &object.HashMap{
		// 微信的接口如果传入接口以外的参数，签名会失败所以这里需要区分对待参数
		"mch_id":     config.GetString("mch_id", ""),
		"nonce_str":  object.RandStringBytesMask(32),
		"sub_mch_id": config.GetString("sub_mch_id", ""),
		"sub_appid":  config.GetString("sub_appid", ""),
	}
	params = object.MergeHashMap(params, base)
	if (*params)["mchid"] == nil {
		(*params)["mch_id"] = config.GetString("mch_id", "")
	} else {
		(*params)["mch_id"] = nil
	}
	params = object.FilterEmptyHashMap(params)

	//options, err := client.AuthSignRequestV2(endpoint, method, params, option)
	options, err := client.AuthSignRequestV2Work(endpoint, method, params, option, appSecret)
	if err != nil {
		return nil, err
	}

	// http client request
	df := client.HttpHelper.Df().
		WithContext(ctx).
		Uri(endpoint).Method(method)

	// 检查是否需要有请求参数配置
	if options != nil {
		// set query key values
		if (*options)["query"] != nil {
			queries := (*options)["query"].(*object.StringMap)
			if queries != nil {
				for k, v := range *queries {
					df.Query(k, v)
				}
			}
		}
		config := (*client.App).GetConfig()
		// 微信如果需要传debug模式
		debug := config.GetBool("debug", false)
		if debug {
			df.Query("debug", "1")
		}

		// set body json
		if (*options)["body"] != nil {
			r := bytes.NewBufferString((*options)["body"].(string))
			df.Body(r)
		}
	}

	returnResponse, err := df.Request()
	if err != nil {
		return returnResponse, err
	}

	return returnResponse, err

}

func (client *Client) AuthSignRequestV2Work(endpoint string, method string, params *object.HashMap, options *object.HashMap, appSecret string) (*object.HashMap, error) {

	var err error

	secretKey, err := (*client.App).GetKey(endpoint)
	if err != nil {
		return nil, err
	}

	strMapParams, err := object.HashMapToStringMap(params)
	if err != nil {
		return nil, err
	}

	// convert StringMap to Power StringMap
	powerStrMapParams, err := power.StringMapToPower(strMapParams)
	if err != nil {
		return nil, err
	}

	// generate md5 workwx_sign with power StringMap
	(*powerStrMapParams)["workwx_sign"] = support.GenerateSignMD5(powerStrMapParams, appSecret)

	// generate md5 signature with power StringMap
	(*powerStrMapParams)["sign"] = support.GenerateSignMD5(powerStrMapParams, secretKey)

	// convert signature to xml content
	var signBody = ""
	if "get" != object.Lower(method) {
		// check need sign body or not
		objPara, err := power.PowerStringMapToObjectStringMap(powerStrMapParams)
		if err != nil {
			return nil, err
		}
		signBody = StringMap2XmlWork(objPara)
	}

	// set body content
	options = object.MergeHashMap(&object.HashMap{
		"body": signBody,
	}, options)

	return options, err
}

func StringMap2XmlWork(obj *object.StringMap) (strXML string) {

	for k, v := range *obj {
		strXML = strXML + fmt.Sprintf("<%s>%s</%s>", k, v, k)
	}
	return "<xml>" + strXML + "</xml>"
}
