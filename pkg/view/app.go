package view

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/constant"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/runner"
	"github.com/projectdiscovery/cvemap/pkg/ui"
	"github.com/projectdiscovery/cvemap/pkg/ui/dialog"
	"github.com/projectdiscovery/gologger"
)

const (
	splashDelay = 3 * time.Second
)

type App struct {
	*ui.App
	Content             *PageStack
	command             *Command
	context             context.Context
	showHeader          bool
	IsPageContentSorted bool
	version             string
	// cancelFn            context.CancelFunc
	// cvemapConfig        config.Cvemap
}

func NewApp() *App {
	a := App{
		App:                 ui.NewApp(),
		Content:             NewPageStack(),
		IsPageContentSorted: false,
	}
	a.Views()["statusIndicator"] = ui.NewStatusIndicator(a.App)
	return &a
}

func (a *App) Init(version string, opts runner.Options, suggestionKeys []string) error {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constant.KeyApp, a)
	ctx = context.WithValue(ctx, constant.KeyOptions, opts)
	a.SetContext(ctx)

	a.version = model.NormalizeVersion(version)
	if err := a.Content.Init(ctx); err != nil {
		return err
	}
	a.Content.Stack.AddListener(a.Menu())
	//a.Content.Stack.AddListener(a.Crumbs())

	a.App.Init()
	a.SetInputCapture(a.keyboard)
	a.bindKeys()

	a.CmdBuff().SetSuggestionFn(a.suggestCommand(suggestionKeys))

	a.layout(ctx)

	a.Main.SwitchToPage(constant.CVEMAP_SCREEN)
	a.command = NewCommand(a)
	a.bindKeys()
	if err := a.command.Init(); err != nil {
		gologger.Error().Msgf(err.Error())
		return err
	}
	if err := a.command.defaultCmd(); err != nil {
		return err
	}
	return nil
}

func (a *App) layout(ctx context.Context) {
	flash := ui.NewFlash(a.App)
	go flash.Watch(ctx, a.Flash().Channel())

	cvemapScreen := tview.NewFlex().SetDirection(tview.FlexRow)
	cvemapScreen.AddItem(a.buildHeader(), 7, 1, false)
	cvemapScreen.AddItem(a.Content, 0, 11, true)
	//cvemapScreen.AddItem(a.Crumbs(), 1, 1, false)
	cvemapScreen.AddItem(flash, 1, 1, false)

	labelsMap := map[string]string{
		"version": a.version,
	}

	infoData := map[string]tview.Primitive{
		"version": ui.NewInfoPrimitive("Version", labelsMap),
	}
	a.Views()["info"] = ui.NewInfo(infoData)
	a.Main.AddPage(constant.CVEMAP_SCREEN, cvemapScreen, true, false)

	a.Main.AddPage(constant.SPLASH_SCREEN, ui.NewSplash(a.version), true, true)
}

func (a *App) SearchInCvemapResource(searchString string) {
	flex, ok := a.Main.GetPrimitive(constant.CVEMAP_SCREEN).(*tview.Flex)
	if !ok {
		gologger.Fatal().Msg("Expecting valid flex view")
		return
	}

	flex.RemoveItemAtIndex(1)

	ctx := context.WithValue(a.GetContext(), constant.KeySearchString, searchString)
	a.SetContext(ctx)
	a.UpdateContext(ctx)
	stackedViews := a.Content.Pages.Stack.Flatten()
	gologger.Info().Msgf("search string: %s", searchString)
	gologger.Info().Msgf("stackedViews: %v", stackedViews[0])
	a.gotoResource(stackedViews[0], "", true)
	// a.App.Flash().Infof("Refreshing %v...", stackedViews[0])
}

// QueueUpdateDraw queues up a ui action and redraw the ui.
func (a *App) QueueUpdateDraw(f func()) {
	if a.Application == nil {
		return
	}
	go func() {
		a.Application.QueueUpdateDraw(f)
	}()
}

func (a *App) Run() error {
	//a.Resume()
	go func() {
		a.Main.SwitchToPage(constant.SPLASH_SCREEN)
		<-time.After(splashDelay)

		a.QueueUpdateDraw(func() {
			a.Main.SwitchToPage(constant.CVEMAP_SCREEN)
			a.toggleHeader(true)
		})
	}()
	a.SetRunning(true)

	if err := a.Application.Run(); err != nil {
		return err
	}

	return nil
}

func (a *App) GetContext() context.Context {
	return a.context
}

func (a *App) SetContext(ctx context.Context) {
	a.context = ctx
}

func (a *App) toggleHeader(header bool) {
	a.showHeader = header

	flex, ok := a.Main.GetPrimitive(constant.CVEMAP_SCREEN).(*tview.Flex)
	if !ok {
		gologger.Fatal().Msg("Expecting valid flex view")
		return
	}

	if a.showHeader {
		flex.RemoveItemAtIndex(0)
		flex.AddItemAtIndex(0, a.buildHeader(), 7, 1, false)
	} else {
		flex.RemoveItemAtIndex(0)
		flex.AddItemAtIndex(0, a.statusIndicator(), 1, 1, false)
	}
}

func (a *App) buildHeader() tview.Primitive {
	header := tview.NewFlex()
	header.SetDirection(tview.FlexColumn)
	if !a.showHeader {
		return header
	}
	header.AddItem(a.info(), 50, 1, false)
	header.AddItem(a.Menu(), 0, 1, false)
	header.AddItem(ui.NewLogo(), 40, 1, false)
	return header
}

func (a *App) suggestCommand(keywords []string) model.SuggestionFunc {
	return func(s string) (entries sort.StringSlice) {
		// if s == "" {
		// 	if a.cmdHistory.Empty() {
		// 		return
		// 	}
		// 	return a.cmdHistory.List()
		// }

		s = strings.ToLower(s)
		suggestionKeys := a.command.alias.Keys()
		suggestionKeys = append(suggestionKeys, keywords...)
		for _, k := range suggestionKeys {
			if k == s {
				continue
			}
			if strings.HasPrefix(k, s) {
				entries = append(entries, strings.Replace(k, s, "", 1))
			}
		}
		if len(entries) == 0 {
			return nil
		}
		entries.Sort()
		return
	}
}

func (a *App) keyboard(evt *tcell.EventKey) *tcell.EventKey {
	if k, ok := a.HasAction(ui.AsKey(evt)); ok && !a.Content.IsTopDialog() {
		return k.Action(evt)
	}

	return evt
}

func (a *App) bindKeys() {
	a.AddActions(ui.KeyActions{
		tcell.KeyCtrlE: ui.NewKeyAction("ToggleHeader", a.toggleHeaderCmd, false),
		tcell.KeyEnter: ui.NewKeyAction("Goto", a.gotoCmd, false),
		tcell.KeyTAB:   ui.NewKeyAction("switch", NewTab(a).tabAction, false),
	})
}

func (a *App) toggleHeaderCmd(evt *tcell.EventKey) *tcell.EventKey {

	a.QueueUpdateDraw(func() {
		a.showHeader = !a.showHeader
		a.toggleHeader(a.showHeader)
	})

	return nil
}

func (a *App) gotoCmd(evt *tcell.EventKey) *tcell.EventKey {
	if a.CmdBuff().IsActive() && !a.CmdBuff().Empty() {
		a.gotoResource(a.GetCmd(), "", true)
		a.ResetCmd()
		return nil
	}

	return evt
}

func (a *App) helpCmd(evt *tcell.EventKey) *tcell.EventKey {
	top := a.Content.Top()

	if top != nil && top.Name() == "help" {
		a.Content.Pop()
		return nil
	}

	if err := a.inject(NewHelp(a)); err != nil {
		a.Flash().Err(err)
	}

	return nil
}

// func (a *App) profileChanged(profile string, index int) {
// 	region := a.GetContext().Value(internal.KeyActiveRegion).(string)
// 	a.refreshSession(profile, region)
// }
// func (a *App) refreshSession(profile string, region string) {

// 	awsConfigInput := aws.AWSConfigInput{
// 		UseLocalStack: a.cloudConfig.UseLocalStack,
// 		Profile:       profile,
// 		Region:        region,
// 	}
// 	cfg, err := aws.GetCfg(awsConfigInput)
// 	//sess, err := aws.GetSession(profile, region)
// 	if err != nil {
// 		a.App.Flash().Err(err)
// 		return
// 	}
// 	ctx := context.WithValue(a.GetContext(), internal.KeySession, cfg)
// 	a.SetContext(ctx)
// 	stackedViews := a.Content.Pages.Stack.Flatten()
// 	a.gotoResource(stackedViews[0], "", true)
// 	a.App.Flash().Infof("Refreshing %v...", stackedViews[0])
// }

func (a *App) gotoResource(cmd, path string, clearStack bool) {
	err := a.command.run(cmd, path, clearStack)
	if err != nil {
		dialog.ShowError(a.Content.Pages, err.Error())
	}
}

func (a *App) inject(c model.Component) error {
	if err := c.Init(a.context); err != nil {
		gologger.Error().Msgf(err.Error(), "component init failed for %q", c.Name())
		dialog.ShowError(a.Content.Pages, err.Error())
	}
	a.Content.Push(c)
	return nil
}

// PrevCmd pops the command stack.
func (a *App) PrevCmd(evt *tcell.EventKey) *tcell.EventKey {
	if !a.Content.IsLast() {
		a.Content.Pop()
	} else {
		a.Main.SwitchToPage(constant.CVEMAP_SCREEN)
	}
	return nil
}

func (a *App) statusIndicator() *ui.StatusIndicator {
	return a.Views()["statusIndicator"].(*ui.StatusIndicator)
}

func (a *App) info() *ui.Info {
	return a.Views()["info"].(*ui.Info)
}
