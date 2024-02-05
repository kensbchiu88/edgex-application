//
//base code: https://github.com/edgexfoundry/edgex-examples/blob/main/application-services/custom/advanced-target-type/main.go 
//doc : https://docs.edgexfoundry.org/3.1/getting-started/ApplicationFunctionsSDK/
//

package main

import (
	"context"
	"os"
	"fmt"
	"net/url"

	"github.com/edgexfoundry/app-functions-sdk-go/v3/pkg"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/dtos"
	"github.com/IOTechSystems/onvif/media"
	"github.com/edgexfoundry/app-functions-sdk-go/v3/pkg/interfaces"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/errors"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/dtos/responses"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/common"
	"github.com/edgexfoundry/go-mod-core-contracts/v3/clients/http/utils"

	"encoding/base64"
	"encoding/json"

)

const (
	serviceKey = "fit-app"
	OnvifDeviceServiceName = "device-onvif-camera"
	profilesCommand = "MediaProfiles"
	streamUriCommand = "StreamUri"
)

type CameraManagementApp struct {
	service        interfaces.ApplicationService
	lc             logger.LoggingClient
	config         *ServiceConfig
}

type StreamUriRequest struct {
	StreamSetup  StreamSetup `json:"StreamSetup"`
	ProfileToken string      `json:"ProfileToken"`
}

type StreamSetup struct {
	Stream    string    `json:"Stream"`
	Transport Transport `json:"Transport"`
}

type Transport struct {
	Protocol string `json:"Protocol"`
}

type OnvifPipelineConfig struct {
	ProfileToken string `json:"profile_token"`
}

type StartPipelineRequest struct {
	Onvif           *OnvifPipelineConfig      `json:"onvif,omitempty"`
}

type PipelineRequest struct {
	URI  string `json:"uri"`
	MqttHost string `json:"mqtt_host"`
	MqttTopic string `json:"mqtt_topic"`
	DeviceName string `json:"device_name"`
}

func main() {
	// turn off secure mode for examples. Not recommended for production
	_ = os.Setenv("EDGEX_SECURITY_SECRET_STORE", "false")

	// 1) First thing to do is to create an instance of an edgex service with your TargetType set
	//    and initialize it. Note that the TargetType is a pointer to an instance of the type.
	// custom target type : https://docs.edgexfoundry.org/3.0/microservices/application/AdvancedTopics/
	// &dtos.SystemEvent{} : from camera-management
	//
	appService, ok := pkg.NewAppServiceWithTargetType(serviceKey, &dtos.SystemEvent{})
	if !ok {
		appService.LoggingClient().Errorf("App Service initialization failed for %s", serviceKey)
		os.Exit(-1)
	}

	//customize

	app := NewCameraManagementApp(appService)

	onvifResponse, err1 := appService.DeviceClient().DevicesByServiceName(context.Background(), OnvifDeviceServiceName, 0, -1)

	// if both failed, throw an error
	if err1 != nil  {
		appService.LoggingClient().Errorf("failed to get devices for the device services: %v", err1)
	}
	deviceName := onvifResponse.Devices[0].Name
	appService.LoggingClient().Infof("----Device Name----: %v", deviceName)

	profileResponse, err2 := app.getProfiles(deviceName)
	if err2 != nil {
		fmt.Errorf("failed to get profiles for device %s, message: %v", deviceName, err2)
	}

	ProfileToken := string(profileResponse.Profiles[0].Token)
	appService.LoggingClient().Infof("ProfileToken: %v", ProfileToken)

	StreamUri, _ := app.getOnvifStreamUri(deviceName, ProfileToken)

	appService.LoggingClient().Infof("----StreamUri----: %v",StreamUri)



	if err := app.Run(); err != nil {
		appService.LoggingClient().Error(err.Error())
		os.Exit(-1)
	}

	os.Exit(0)
}

func NewCameraManagementApp(service interfaces.ApplicationService) *CameraManagementApp {
	return &CameraManagementApp{
		service:      service,
		lc:           service.LoggingClient(),
		config:       &ServiceConfig{},
	}
}

func (app *CameraManagementApp) getProfiles(deviceName string) (media.GetProfilesResponse, error) {
	resp := media.GetProfilesResponse{}
	err := app.issueGetCommandForResponse(context.Background(), deviceName, profilesCommand, &resp)
	return resp, err
}

func (app *CameraManagementApp) issueGetCommandForResponse(ctx context.Context, deviceName string, commandName string,
	response interface{}) error {

	app.lc.Info("----issueGetCommandForResponse----")

	event, err := app.issueGetCommand(ctx, deviceName, commandName)
	if err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, fmt.Sprintf("failed to issue get command %s for device %s", commandName, deviceName), err)
	}
	return app.parseResponse(commandName, event, response)
}

//echo -n '{"ProfileToken": "ProfileToken_1"}' | base64    ->  jsonObject
//POST http://localhost:59882/api/v3/device/name/onvif-simulator-10000/StreamUri?jsonObject=eyJQcm9maWxlVG9rZW4iOiAiUHJvZmlsZVRva2VuXzEifQ==
func (app *CameraManagementApp) getOnvifStreamUri(deviceName string, profileToken string) (string, error) {
	req := StreamUriRequest{ProfileToken: profileToken}
	resp := media.GetStreamUriResponse{}
	err := app.issueGetCommandWithJsonForResponse(context.Background(), deviceName, streamUriCommand, req, &resp)
	if err != nil {
		return "", err
	}
	return string(resp.MediaUri.Uri), nil
}

func (app *CameraManagementApp) issueGetCommand(ctx context.Context, deviceName string, commandName string) (*responses.EventResponse, error) {
	app.lc.Infof("----issueGetCommand---- deviceName:%s, commandName:%s", deviceName, commandName)
	return app.service.CommandClient().IssueGetCommandByName(ctx, deviceName, commandName, false, true)
}

func (app *CameraManagementApp) issueGetCommandWithJsonForResponse(ctx context.Context, deviceName string, commandName string,
	jsonValue interface{}, response interface{}) error {

	event, err := app.issueGetCommandWithJson(ctx, deviceName, commandName, jsonValue)
	if err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, fmt.Sprintf("failed to issue get command %s for device %s", commandName, deviceName), err)
	}
	return app.parseResponse(commandName, event, response)
}

func (app *CameraManagementApp) issueGetCommandWithJson(ctx context.Context, deviceName string, commandName string, jsonValue interface{}) (*responses.EventResponse, error) {
	jsonStr, err := json.Marshal(jsonValue)
	if err != nil {
		return nil, err
	}

	return app.service.CommandClient().IssueGetCommandByNameWithQueryParams(ctx, deviceName, commandName,
		map[string]string{"jsonObject": base64.URLEncoding.EncodeToString(jsonStr)})
}

func (app *CameraManagementApp) parseResponse(commandName string, event *responses.EventResponse, response interface{}) error {
	val := event.Event.Readings[0].ObjectValue

	app.lc.Infof("----parseResponse----: %v", val)

	js, err := json.Marshal(val)
	if err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, fmt.Sprintf("failed to marshal %s object value as json object", commandName), err)
	}

	err = json.Unmarshal(js, response)
	if err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, fmt.Sprintf("failed to unmarhal %s json object to response type %T", commandName, response), err)
	}

	return nil
}

func (app *CameraManagementApp) Run() error {
	if err := app.service.LoadCustomConfig(app.config, "AppCustom"); err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, "failed to load custom configuration", err)
	}

	var err error
	// Query EVAM pipeline status
	/*
	for i := 0; i < maxRetries; i++ {
		app.lc.Infof("Querying EVAM pipeline statuses.")
		if err = app.queryAllPipelineStatuses(); err != nil {
			app.lc.Errorf("Unable to query EVAM pipeline statuses. Is EVAM running? %s", err.Error())
			time.Sleep(time.Second)
		} else {
			break // no error, so lets continue
		}
	}
	if err != nil {
		app.lc.Errorf("Unable to query EVAM pipeline statuses after %d tries.", maxRetries)
		return err // exit. we do not want to run if evam is not accessible
	}
	*/

	// Add routes
	/*
	if err := app.addRoutes(); err != nil {
		return err
	}
	*/

	// Subscribe to events.
	if err := app.service.SetDefaultFunctionsPipeline(app.processEdgeXDeviceSystemEvent); err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, "failed to set default pipeline to processEdgeXEvent", err)
	}

	// 針對現有的Onvif Device，啟動Pipeline
	devices, err := app.getAllDevices()
	if err != nil {
		app.lc.Errorf("no devices found: %s", err.Error())
	} else {
		for _, device := range devices {
			if err = app.startDefaultPipeline(device); err != nil {
				app.lc.Errorf("Error starting default pipeline for %s, %v", device.Name, err)
			}
		}
	}

	if err = app.service.Run(); err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, "failed to run pipeline", err)
	}

	return nil
}

// processEdgeXDeviceSystemEvent is the function that is called when an EdgeX Device System Event is received
func (app *CameraManagementApp) processEdgeXDeviceSystemEvent(_ interfaces.AppFunctionContext, data interface{}) (bool, interface{}) {
	if data == nil {
		return false, fmt.Errorf("processEdgeXDeviceSystemEvent: was called without any data")
	}

	systemEvent, ok := data.(dtos.SystemEvent)
	if !ok {
		return false, fmt.Errorf("type received %T is not a SystemEvent", data)
	}

	if systemEvent.Type != common.DeviceSystemEventType {
		return false, fmt.Errorf("system event type is not " + common.DeviceSystemEventType)
	}

	device := dtos.Device{}
	err := systemEvent.DecodeDetails(&device)
	if err != nil {
		return false, fmt.Errorf("failed to decode device details: %v", err)
	}

	switch systemEvent.Action {
	case common.SystemEventActionAdd:
		if err = app.startDefaultPipeline(device); err != nil {
			return false, err
		}
	/*
	case common.SystemEventActionDelete:
		// stop any running pipelines for the deleted device
		if info, found := app.getPipelineInfo(device.Name); found {
			if err = app.stopPipeline(device.Name, info.Id); err != nil {
				return false, fmt.Errorf("error stopping pipleline for device %s, %v", device.Name, err)
			}
		}
	*/
	default:
		app.lc.Debugf("System event action %s is not handled", systemEvent.Action)
	}

	return false, nil
}


func (app *CameraManagementApp) startDefaultPipeline(device dtos.Device) error {
	startPipelineRequest := StartPipelineRequest{
	}

	protocol, ok := device.Protocols["Onvif"]
	if ok {
		app.lc.Debugf("Onvif protocol information found for device: %s message: %v", device.Name, protocol)
		profileResponse, err := app.getProfiles(device.Name)
		if err != nil {
			return fmt.Errorf("failed to get profiles for device %s, message: %v", device.Name, err)

		}

		app.lc.Debugf("Onvif profile information found for device: %s message: %v", device.Name, profileResponse)
		startPipelineRequest.Onvif = &OnvifPipelineConfig{
			ProfileToken: string(profileResponse.Profiles[0].Token),
		}
	} else {
		app.lc.Debugf("Not Onvif device: %s", device.Name)
		return fmt.Errorf("Not Onvif device: %s", device.Name)
	}

	app.lc.Debugf("Starting default pipeline for device %s", device.Name)
	if err := app.startPipeline(device.Name, startPipelineRequest); err != nil {
		return fmt.Errorf("pipeline failed to start for device %s, message: %v", device.Name, err)
	}

	return nil
}

func (app *CameraManagementApp) startPipeline(deviceName string, sr StartPipelineRequest) error {
	streamUri, err := app.getOnvifStreamUri(deviceName, sr.Onvif.ProfileToken)
	if err != nil {
		return err
	}
	app.lc.Infof("Received stream uri for the device %s: %s", deviceName, streamUri)

	// set the secret name to be the onvif one by default
	secretName := onvifauth

	body, err := app.createPipelineRequestBody(streamUri, deviceName, secretName)
	if err != nil {
		return errors.NewCommonEdgeX(errors.KindServerError, "failed to create DLStreamer pipeline request body", err)
	}

	var res interface{}
	baseUrl, err := url.Parse(app.config.AppCustom.EvamBaseUrl)
	if err != nil {
		return err
	}
	reqPath := "/pipeline"


	if err = issuePostRequest(context.Background(), &res, baseUrl.String(), reqPath, body); err != nil {
		err = errors.NewCommonEdgeX(errors.KindServerError, "POST request to start EVAM pipeline failed", err)
		// if we started the streaming on usb camera, we need to stop it
		/*
		if sr.USB != nil {
			if _, err2 := app.stopStreaming(deviceName); err2 != nil {
				err = errors.NewCommonEdgeX(errors.KindServerError, fmt.Sprintf("failed to stop streaming usb camera %s", deviceName), err)
			}
		}
		*/
		return err
	}

	app.lc.Infof("Successfully started EVAM pipeline for the device %s", deviceName)

	return nil
}

func issuePostRequest(ctx context.Context, res interface{}, baseUrl string, reqPath string, jsonValue []byte) (err error) {
	return utils.PostRequest(ctx, &res, baseUrl, reqPath, jsonValue, common.ContentTypeJSON, nil)
}

func (app *CameraManagementApp) createPipelineRequestBody(streamUri string, deviceName string, secretName string) ([]byte, error) {
	uri, err := url.Parse(streamUri)
	if err != nil {
		return nil, err
	}

	if creds, err := app.tryGetCredentials(secretName); err != nil {
		app.lc.Warnf("Error retrieving %s secret from the SecretStore: %s", secretName, err.Error())
	} else {
		uri.User = url.UserPassword(creds.Username, creds.Password)
	}

	pipelineData := PipelineRequest{
		URI:  uri.String(),
		MqttHost: app.config.AppCustom.MqttAddress,
		MqttTopic: app.config.AppCustom.MqttTopic,
		DeviceName: deviceName,
	}

	pipeline, err := json.Marshal(pipelineData)
	if err != nil {
		return pipeline, err
	}

	return pipeline, nil
}

func (app *CameraManagementApp) getAllDevices() ([]dtos.Device, error) {
	onvifResponse, err1 := app.service.DeviceClient().DevicesByServiceName(context.Background(), app.config.AppCustom.OnvifDeviceServiceName, 0, -1)

	// if both failed, throw an error
	if err1 != nil {
		return nil, fmt.Errorf("failed to get devices for the device services: %v", err1)
	}

	var devices []dtos.Device
	if err1 == nil {
		// if the first one succeeded, just overwrite the slice
		devices = onvifResponse.Devices
	}

	if len(devices) <= 0 {
		return nil, errors.NewCommonEdgeX(errors.KindServerError, fmt.Sprintf("no devices registered yet for the device services %s",
			app.config.AppCustom.OnvifDeviceServiceName), nil)
	}

	return devices, nil
}