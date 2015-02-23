//
//  LeakDetectorPrettyViewController.h
//  Leak Detector
//
//  Created by David Naylor on 3/23/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Quartz/Quartz.h>

@interface LeakDetectorPrettyViewController : NSViewController

@property (nonatomic, strong) NSDictionary* leakInfoDict;
@property (nonatomic, strong) NSSet* googleSearches;
@property (nonatomic, strong) NSSet* webPages;
@property (nonatomic, strong) NSSet* amazonProducts;
@property (nonatomic, strong) NSMutableArray* images;

@property (strong) IBOutlet NSTextField *lblOS;
@property (strong) IBOutlet NSTextField *lblLanguages;
@property (strong) IBOutlet NSTextField *lblBrowsers;
@property (strong) IBOutlet IKImageBrowserView *imageBrowser;

@end
