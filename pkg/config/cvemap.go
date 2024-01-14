package config

type Active struct {
	View string `yaml:"view"`
}

type Cvemap struct {
	EnableMouse bool    `yaml:"enableMouse"`
	Headless    bool    `yaml:"headless"`
	Logoless    bool    `yaml:"logoless"`
	Crumbsless  bool    `yaml:"crumbsless"`
	Active      *Active `yaml:"active"`
}

// NewCloudlens create a new Cloudlens configuration.
func NewCvemap() *Cvemap {
	return &Cvemap{}
}
