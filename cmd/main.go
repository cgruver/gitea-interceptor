package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	secretInformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"
	"knative.dev/pkg/injection"
	"knative.dev/pkg/signals"
)

type GiteaHookHeader struct {
	XGiteaDelivery  string `json:"X-Gitea-Delivery,omitempty"`
	XGiteaSignature string `json:"X-Gitea-Signature,omitempty"`
	XGiteaEvent     string `json:"X-Gitea-Event,omitempty"`
}

type GiteaHookParams struct {
	ValidEvents []string  `json:"validEvents,omitempty"`
	Secret      SecretRef `json:"secretRef,omitempty"`
}
type SecretRef struct {
	SecretKey  string `json:"secretKey,omitempty"`
	SecretName string `json:"secretName,omitempty"`
}

var secretLister v1.SecretLister

func main() {

	ctx := signals.NewContext()
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to build config: %v", err)
	}

	ctx, startInformer := injection.EnableInjectionOrDie(ctx, clusterConfig)
	startInformer()
	secretLister = secretInformer.Get(ctx).Lister()

	http.HandleFunc("/ready", readiness)

	http.HandleFunc("/gitea", interceptor)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", 8080), nil))
}

func readiness(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
}

func interceptor(writer http.ResponseWriter, request *http.Request) {
	var irBody []byte
	var err error

	if irBody, err = ioutil.ReadAll(request.Body); err != nil {
		log.Printf("failed to parse body: %w", err)
	}

	var ir triggersv1.InterceptorRequest
	if err := json.Unmarshal(irBody, &ir); err != nil {
		log.Printf("failed to parse body as InterceptorRequest: %w", err)
	}

	var hookHeader http.Header = ir.Header

	var hookParams GiteaHookParams
	params, err := json.Marshal(ir.InterceptorParams)
	if err != nil {
		log.Printf("error marshaling json: %w", err)
		reply(writer, false, fmt.Sprintf("error marshaling json: %w", err))
	}
	if err := json.Unmarshal(params, &hookParams); err != nil {
		log.Printf("failed to parse Interceptor Params as GiteaHookParams: %w", err)
		reply(writer, false, fmt.Sprintf("failed to parse Interceptor Params as GiteaHookParams: %w", err))
	}

	validEvent := false
	hookEvent := hookHeader.Get("X-Gitea-Event")
	for _, event := range hookParams.ValidEvents {
		if hookEvent == event {
			validEvent = true
			break
		}
	}
	if !validEvent {
		log.Printf("Hook event is not in the Valid Event list: %s", hookEvent)
		reply(writer, false, fmt.Sprintf("Hook event is not in the Valid Event list: %s", hookEvent))
	}

	ns, _ := triggersv1.ParseTriggerID(ir.Context.TriggerID)
	secret, err := secretLister.Secrets(ns).Get(hookParams.Secret.SecretName)
	if err != nil {
		log.Printf("error getting secret: %w", err)
	}
	secretToken := secret.Data[hookParams.Secret.SecretKey]

	hashFunc := sha256.New
	mac := hmac.New(hashFunc, secretToken)
	mac.Write([]byte(ir.Body))
	computedSignature := mac.Sum(nil)
	signature, err := hex.DecodeString(hookHeader.Get("X-Gitea-Signature"))
	if err != nil {
		log.Printf("error decoding string from byte[] json: %w", err)
		reply(writer, false, fmt.Sprintf("error decoding string from byte[] json: %w", err))
	}
	log.Printf("Expected - %s", hookHeader.Get("X-Gitea-Signature"))
	log.Printf("Computed - %s", hex.EncodeToString(computedSignature))

	if hmac.Equal(computedSignature, signature) {
		reply(writer, true, "Hook Signature Validated")
	} else {
		log.Printf("Signature check Failed: expected - %s, computed - %s", hex.EncodeToString(signature), hex.EncodeToString(computedSignature))
		reply(writer, false, fmt.Sprintf("Signature check Failed: expected - %s, computed - %s", hex.EncodeToString(signature), hex.EncodeToString(computedSignature)))
	}
}

func reply(writer http.ResponseWriter, c bool, m string) error {
	var response triggersv1.InterceptorResponse
	response.Continue = c
	response.Status.Message = m
	r, err := json.Marshal(response)
	if err != nil {
		log.Printf("error marshaling json: %w", err)
		return err
	}
	writer.Header().Add("Content-Type", "application/json")
	n, err := writer.Write(r)
	if err != nil {
		log.Printf("Failed to write response for gitea event. Bytes written: %d. Error: %w", n, err)
		return err
	}
	return nil
}
