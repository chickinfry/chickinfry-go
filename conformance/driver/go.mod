module github.com/chickinfry/chickinfry-go/conformance/driver

go 1.26.6

require (
	chickinfry-client-auth v0.0.0
	chickinfry-client-empty-session v0.0.0
	chickinfry-client-plain v0.0.0
	github.com/chickinfry/chickinfry-go v0.0.0-20261011073655-2d8ecd63e4d0
)

require golang.org/x/net v0.63.0 // indirect

replace github.com/chickinfry/chickinfry-go => ../..
