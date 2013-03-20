//
//  AppDelegate.h
//  Leak Detector
//
//  Created by David Naylor on 3/11/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "LeakDetectorBackgroundAnalyzer.h"

@interface AppDelegate : NSObject <NSApplicationDelegate, LeakInfoDelegate, AnalyzerActivityListener>

@property (assign) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSView *leakDetectorInfoViewContainer;
@property (weak) IBOutlet NSScrollView *leakDetectorInfoScrollView;
- (IBAction)analyzeTracePressed:(id)sender;
@property (weak) IBOutlet NSTextField *statusLabel;
@property (weak) IBOutlet NSProgressIndicator *progressIndicator;
- (IBAction)startSniffingPressed:(id)sender;
- (IBAction)stopSniffingPressed:(id)sender;

@end
