//
//  LeakDetectorInfoViewController.h
//  Leak Detector
//
//  Created by David Naylor on 3/11/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface LeakDetectorInfoViewController : NSViewController <NSOutlineViewDataSource, NSOutlineViewDelegate>

@property (atomic, strong) NSDictionary *leakInfoDict;
@property (strong) IBOutlet NSOutlineView *leakInfoOutlineView;

@end
