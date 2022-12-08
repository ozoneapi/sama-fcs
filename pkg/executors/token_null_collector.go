package executors

import (
	"fmt"

	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/executors/events"
	"bitbucket.org/ozoneapi/sama-conformance-suite/pkg/model"
	log "github.com/sirupsen/logrus"
)

// NewNullTokenCollector -
func NewNullTokenCollector(consentIds ConsentTokens, doneFunc func(), events events.Events, ctx *model.Context) TokenCollector {
	return &NullCollector{
		doneFunc:     doneFunc,
		collected:    0,
		events:       events,
		consentTable: consentIds,
		ctx:          ctx,
	}
}

// NullCollector -
type NullCollector struct {
	doneFunc     func()
	collected    int
	consentTable ConsentTokens
	events       events.Events
	ctx          *model.Context
}

// Collect -
func (n *NullCollector) Collect(tokenName, accessToken string) error {
	log.Infof("NullCollector: collect token : %s  %s", tokenName, accessToken)
	n.collected++
	//accountToken0001
	//n.addAccessToken(tokenName, accessToken)
	token := fmt.Sprintf("accountToken00%2.2d", n.collected)
	log.Debug("Adding token: %s %s", token, accessToken)
	n.addAccessToken(tokenName, accessToken)
	n.ctx.PutString(token, accessToken)
	if n.isDone() {
		tokenNames := []string{}
		for _, item := range n.consentTable {
			tokenNames = append(tokenNames, item.TokenName)
		}

		acquiredAllAccessTokens := events.NewAcquiredAllAccessTokens(tokenNames)
		n.events.AddAcquiredAllAccessTokens(acquiredAllAccessTokens)
		n.events.AllTokensChannel()

		if n.doneFunc != nil {
			log.Debug("NullCollector: calling doneFunc ...")
			n.doneFunc()
		}
	}

	return nil
}

func (n *NullCollector) addAccessToken(tokenName, accessToken string) {

	for k, item := range n.consentTable {
		if tokenName == item.TokenName {
			item.AccessToken = accessToken
			n.consentTable[k] = item
			n.collected++

			acquiredAccessToken := events.NewAcquiredAccessToken(tokenName)
			n.events.AddAcquiredAccessToken(acquiredAccessToken)
		}
	}
}

// Tokens -
func (n *NullCollector) Tokens() ConsentTokens {
	return n.consentTable
}
func (n *NullCollector) isDone() bool {
	return n.collected == len(n.consentTable)
}
