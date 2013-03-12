//
//  AppDelegate.m
//  Leak Detector
//
//  Created by David Naylor on 3/11/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import "AppDelegate.h"
#import "LeakDetectorInfoViewController.h"
#import "LeakDetectorBackgroundAnalyzer.h"

@interface AppDelegate()
@property (nonatomic, strong) LeakDetectorInfoViewController *leakDetectorInfoViewController;
@property (nonatomic, strong) LeakDetectorBackgroundAnalyzer *analyzer;
@end

@implementation AppDelegate

@synthesize leakDetectorInfoViewController = _leakDetectorInfoViewController;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
    
    // TODO: move this to separate WindowController?
    self.leakDetectorInfoViewController = [[LeakDetectorInfoViewController alloc] initWithNibName:@"LeakDetectorInfoViewController" bundle:nil];
    [self.leakDetectorInfoViewController.view setFrameSize:self.leakDetectorInfoScrollView.contentView.frame.size];
    [self.leakDetectorInfoScrollView setDocumentView:self.leakDetectorInfoViewController.view];
    [self.leakDetectorInfoViewController.view setAutoresizingMask: NSViewWidthSizable|NSViewHeightSizable];
    
    // Prepare the analyzer
    self.analyzer = [[LeakDetectorBackgroundAnalyzer alloc] init];
    self.analyzer.infoDelegate = self;
    [self.analyzer addActivityListener:self];
    
}

-(void) updateLeakInfo:(NSDictionary *)infoDict {
    if (self.leakDetectorInfoViewController) {
        self.leakDetectorInfoViewController.leakInfoDict = infoDict;
    }
}

-(void) analyzeTraceFile:(NSURL*)url {
    
}

- (IBAction)analyzeTracePressed:(id)sender {    
    NSOpenPanel* openPanel = [NSOpenPanel openPanel];
	
	NSArray* fileTypes = [NSArray arrayWithObjects:@"pcap", nil];
	[openPanel setAllowsMultipleSelection:NO];
	[openPanel setMessage:@"Choose a trace file to analyze:"];
    [openPanel setAllowedFileTypes:fileTypes];
    //[openPanel setDirectoryURL:[NSURL fileURLWithPath:@"/Library/Desktop Pictures/"]];
    [openPanel beginSheetModalForWindow:self.window completionHandler:^(NSInteger result) {
        
        if (result == NSOKButton)
        {
            if ([[openPanel URL] isFileURL]) {
                
                [self.analyzer analyzeTrace: [[openPanel URL] path]];

            }
        }
        
    }];
}

-(void)analyzerDidStart:(LeakDetectorBackgroundAnalyzer *)analyzer {
    self.statusLabel.stringValue = @"Analyzing packet trace...";
    [self.progressIndicator startAnimation:self];
}

-(void)analyzerDidFinish:(LeakDetectorBackgroundAnalyzer *)analyzer {
    [self.progressIndicator stopAnimation:self];
    self.statusLabel.stringValue = @"Finished.";
}
@end
