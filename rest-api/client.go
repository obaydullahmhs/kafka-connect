package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	catalog "kubedb.dev/apimachinery/apis/catalog/v1alpha1"
	dapi "kubedb.dev/apimachinery/apis/dashboard/v1alpha1"
)

type EDClient interface {
	GetHealthStatus() (*Health, error)
	GetStateFromHealthResponse(health *Health) (dapi.DashboardServerState, error)
}

//type ClientOptions struct {
//	KClient   client.Client
//	Dashboard *dapi.ElasticsearchDashboard
//	ESVersion *catalog.ElasticsearchVersion
//	DB        *api.Elasticsearch
//	Ctx       context.Context
//	Secret    *core.Secret
//	Log       logr.Logger
//}

type Config struct {
	host             string
	api              string
	username         string
	password         string
	connectionScheme string
	transport        *http.Transport
	//log              logr.Logger
}

type Health struct {
	ConnectionResponse Response
	OverallState       string
	StateFailedReason  map[string]string
}

type Response struct {
	Code   int
	header http.Header
	body   io.ReadCloser
}

type ResponseBody struct {
	Name    string                 `json:"name"`
	UUID    string                 `json:"uuid"`
	Version map[string]interface{} `json:"version"`
	Status  map[string]interface{} `json:"status"`
	Metrics map[string]interface{} `json:"metrics"`
}

func GetDashboardClient(opt *ClientOptions) (EDClient, error) {
	config := Config{
		host: getHostPath(opt.Dashboard),
		api:  "/",
		transport: &http.Transport{
			IdleConnTimeout: time.Second * 3,
			DialContext: (&net.Dialer{
				Timeout: time.Second * 30,
			}).DialContext,
		},
		connectionScheme: "http",
	}

	config.log = opt.Log

	// If EnableSSL is true set tls config,
	// provide client certs and root CA
	if opt.Dashboard.Spec.EnableSSL {
		var certSecret core.Secret
		err := opt.KClient.Get(opt.Ctx, types.NamespacedName{
			Namespace: opt.Dashboard.Namespace,
			Name:      opt.Dashboard.CertificateSecretName(dapi.ElasticsearchDashboardServerCert),
		}, &certSecret)
		if err != nil {
			config.log.Error(err, "failed to get serverCert secret")
			return nil, err
		}

		// get tls cert, clientCA and rootCA for tls config
		// use server cert ca for rootca as issuer ref is not taken into account
		clientCA := x509.NewCertPool()
		rootCA := x509.NewCertPool()

		crt, err := tls.X509KeyPair(certSecret.Data[core.TLSCertKey], certSecret.Data[core.TLSPrivateKeyKey])
		if err != nil {
			config.log.Error(err, "failed to create certificate for TLS config")
			return nil, err
		}
		clientCA.AppendCertsFromPEM(certSecret.Data[dapi.CaCertKey])
		rootCA.AppendCertsFromPEM(certSecret.Data[dapi.CaCertKey])

		config.transport.TLSClientConfig = &tls.Config{
			Certificates: []tls.Certificate{crt},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCA,
			RootCAs:      rootCA,
			MaxVersion:   tls.VersionTLS13,
		}
	}

	var username, password string

	// if security is enabled set database credentials in clientConfig
	if !opt.DB.Spec.DisableSecurity {

		if value, ok := opt.Secret.Data[core.BasicAuthUsernameKey]; ok {
			username = string(value)
		} else {
			config.log.Info(fmt.Sprintf("Failed for secret: %s/%s, username is missing", opt.Secret.Namespace, opt.Secret.Name))
			return nil, errors.New("username is missing")
		}

		if value, ok := opt.Secret.Data[core.BasicAuthPasswordKey]; ok {
			password = string(value)
		} else {
			config.log.Info(fmt.Sprintf("Failed for secret: %s/%s, password is missing", opt.Secret.Namespace, opt.Secret.Name))
			return nil, errors.New("password is missing")
		}

		config.username = username
		config.password = password
	}

	// parse version
	version, err := semver.NewVersion(opt.ESVersion.Spec.Version)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse version")
	}

	switch {
	// for Elasticsearch 7.x.x and OpenSearch 1.x.x
	case (opt.ESVersion.Spec.AuthPlugin == catalog.ElasticsearchAuthPluginXpack && version.Major() <= 7) ||
		(opt.ESVersion.Spec.AuthPlugin == catalog.ElasticsearchAuthPluginOpenSearch && (version.Major() == 1 || version.Major() == 2)):
		newClient := resty.New()
		newClient.SetTransport(config.transport).SetScheme(config.connectionScheme).SetBaseURL(config.host)
		newClient.SetHeader("Accept", "application/json")
		newClient.SetBasicAuth(config.username, config.password)
		newClient.SetTimeout(time.Second * 30)

		return &EDClientV7{
			Client: newClient,
			log:    config.log,
			Config: &config,
		}, nil

	case opt.ESVersion.Spec.AuthPlugin == catalog.ElasticsearchAuthPluginXpack && version.Major() == 8:
		newClient := resty.New()
		newClient.SetTransport(config.transport).SetScheme(config.connectionScheme).SetBaseURL(config.host)
		newClient.SetHeader("Accept", "application/json")
		newClient.SetBasicAuth(config.username, config.password)
		newClient.SetTimeout(time.Second * 30)

		return &EDClientV8{
			Client: newClient,
			log:    config.log,
			Config: &config,
		}, nil
	}

	return nil, fmt.Errorf("unknown version: %s", opt.ESVersion.Name)
}

// return host path in
// format https://svc_name.namespace.svc:5601/api/status
func getHostPath(dashboard *dapi.ElasticsearchDashboard) string {
	//return fmt.Sprintf("%v://%s.%s.svc:%d", dashboard.GetConnectionScheme(), dashboard.ServiceName(), dashboard.GetNamespace(), dapi.ElasticsearchDashboardRESTPort)
	return "http://172.104.37.95:8083"
}
