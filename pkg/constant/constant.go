package constant

// ContextKey represents context key.
type ContextKey string

const (
	KeyApp          ContextKey = "app"
	KeyAliases      ContextKey = "aliases"
	KeyOptions      ContextKey = "options"
	KeyFactory      ContextKey = "factory"
	KeySearchString ContextKey = "searchString"

	Help            string = "help"
	LowercaseH      string = "h"
	QuestionMark    string = "?"
	Quit            string = "quit"
	LowercaseQ      string = "q"
	UppercaseQ      string = "Q"
	QFactorial      string = "q!"
	Aliases         string = "aliases"
	Alias           string = "alias"
	LowercaseA      string = "a"
	LowercaseCvemap string = "cvemap"
)

const (
	CVEMAP_SCREEN = "cvemap"
	SPLASH_SCREEN = "splash"
)
