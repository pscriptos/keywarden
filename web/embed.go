// Keywarden - Centralized SSH Key Management and Deployment
// Copyright (C) 2026 Patrick Asmus (scriptos)
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import "embed"

//go:embed templates/* templates/layout/*
var TemplateFS embed.FS

//go:embed static/css/* static/css/fonts/* static/js/* static/favicon.svg
var StaticFS embed.FS
