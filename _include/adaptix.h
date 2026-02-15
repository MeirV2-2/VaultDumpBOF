/*
 * AdaptixC2 Extended BOF API
 * Provides Adaptix-specific functions beyond standard beacon.h
 */
#pragma once
#include "beacon.h"

DECLSPEC_IMPORT void AxAddScreenshot(char* note, char* data, int len);
DECLSPEC_IMPORT void AxDownloadMemory(char* filename, char* data, int len);
