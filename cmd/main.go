package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	"k8s.io/client-go/rest"
	secretInformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"
	"knative.dev/pkg/injection"
	"knative.dev/pkg/signals"
)

const giteaSecret = "GITEA_SECRET"

type GiteaHookHeader struct {
	xGiteaDelivery  string   `json:"X-Gitea-Delivery,omitempty"`
	xGiteaSignature string   `json:"X-Gitea-Signature,omitempty"`
	xGiteaEvent     string   `json:"X-Gitea-Event,omitempty"`
}

type GiteaHookParams struct {
	validEvents     []string `json:"validEvents,omitempty"`
	secretRef       SecretRef
}
type SecretRef struct {
	SecretKey  string `json:"secretKey,omitempty"`
	SecretName string `json:"secretName,omitempty"`
}

func main() {

	ctx := signals.NewContext()
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to build config: %v", err)
	}

	ctx, startInformer := injection.EnableInjectionOrDie(ctx, clusterConfig)
	secretLister := secretInformer.Get(ctx).Lister()

	var kubeSecret SecretRef
	secret := os.Getenv(giteaSecret)
	if secret == "" {
		log.Fatalf("No secret token given")
	}

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {

		if request.Header.Get("Content-Type") != "application/json" {
			log.Fatalf("Webhook request has unsupported Content-Type.  Expected \"application/json\"")
		}
		var irBody byte[]
		if irBody, err = ioutil.ReadAll(request.Body); err != nil {
			log.Fatalf("failed to parse body: %w", err)
		}

		var ir triggersv1.InterceptorRequest
		if err := json.Unmarshal(irBody, &ir); err != nil {
			log.Fatalf("failed to parse body as InterceptorRequest: %w", err)
		}

		var hookParams GiteaHookParams
		if err := json.Unmarshal(ir.InterceptorParams, &hookParams); err != nil {
			log.Fatalf("failed to parse Interceptor Params as GiteaHookParams: %w", err)
		}

		ns, _ := triggersv1.ParseTriggerID(ir.Context.TriggerID)
		secret, err := secretLister.Secrets(ns).Get(hookParams.SecretRef.SecretName)
		if err != nil {
			log.Fatalf("error getting secret: %w", err)
		}
		secretToken := secret.Data[p.SecretRef.SecretKey]

		
		var hookHeader GiteaHookHeader
		if err := json.Unmarshal((ir.Header), &hookHeader); err != nil {
			log.Fatalf("error getting webhook header as GiteaHookHeader: %w", err)
		}
		ns, _ := triggersv1.ParseTriggerID(r.Context.TriggerID)


		var hashFunc func() hash.Hash
		hashFunc = sha256.New
		mac := hmac.New(hashFunc, secretToken)
		mac.Write([]byte(ir.Body))
		expectedSignature := mac.Sum()
		signature, err := hex.DecodeString(hookHeader.xGiteaSignature)
		if !hmac.Equal(expectedSignature, signature) {
			http.Error(writer, fmt.Sprint("Signature check Failed: expected - %s, computed - %s", expectedSignature, signature), http.StatusBadRequest)
		}
		n, err := writer.Write(request)
		if err != nil {
			log.Printf("Failed to write response for gitea event ID: %s. Bytes writted: %d. Error: %q", id, n, err)
		}
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", 8080), nil))
}
