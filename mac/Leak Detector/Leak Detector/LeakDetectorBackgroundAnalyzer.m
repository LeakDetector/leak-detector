//
//  LeakDetectorBackgroundAnalyzer.m
//  Leak Detector
//
//  Created by David Naylor on 3/11/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import "LeakDetectorBackgroundAnalyzer.h"

@interface LeakDetectorBackgroundAnalyzer()
@property (nonatomic, strong) NSMutableSet *listeners;
@end

@implementation LeakDetectorBackgroundAnalyzer
@synthesize listeners = _listeners;
-(NSMutableSet*)listeners {
    if (!_listeners) {
        _listeners = [[NSMutableSet alloc]initWithCapacity:5];
    }
    return _listeners;
}

@synthesize infoDelegate = _infoDelegate;

-(void) startAnalyzeRealTime {
    
}

-(void) stopAnalyzeRealTime {
    
}

-(NSDictionary*) analyzeTraceHelper:(NSString*)pcapFile {
    NSString *BASE_PATH = @"/Users/dnaylor/Documents/School/CMU/leak-detector";
    
    NSTask *task;
    task = [[NSTask alloc] init];
    [task setLaunchPath: @"/usr/bin/python"];
    
    NSArray *arguments;
    arguments = [NSArray arrayWithObjects:[BASE_PATH stringByAppendingPathComponent:@"analyzer.py"], @"-v", pcapFile, nil];
    [task setArguments: arguments];
    
    NSPipe *pipe;
    pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    NSFileHandle *file;
    file = [pipe fileHandleForReading];
    
    [task launch];
    
    NSData *data;
    data = [file readDataToEndOfFile];
    
    // parse JSON
    NSError *error = nil;
    NSDictionary *info_dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error) {
        NSLog(@"Error parsing JSON");
        return nil;
    } else {
        return info_dict;
    }

}

-(void) analyzeTrace:(NSString*)pcapFile {
    
    dispatch_queue_t q_default = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(q_default, ^{
        
        NSDictionary* info_dict = [self analyzeTraceHelper:pcapFile];
        
        dispatch_queue_t q_main = dispatch_get_main_queue();
        dispatch_async(q_main, ^{
            [self.infoDelegate updateLeakInfo:info_dict];
            [self notifyListenersFinished];
        });
    });
    [self notifyListenersStarted];
}

-(void) addActivityListener:(id<AnalyzerActivityListener>)listener {
    [self.listeners addObject:listener];
}

-(void) removeActivityListener:(id<AnalyzerActivityListener>)listener {
    [self.listeners removeObject:listener];  // TODO: check that listener is in set?
}

-(void) notifyListenersStarted {
    for (id<AnalyzerActivityListener> listener in self.listeners) {
        [listener analyzerDidStart:self];
    }
}

-(void) notifyListenersFinished {
    for (id<AnalyzerActivityListener> listener in self.listeners) {
        [listener analyzerDidFinish:self];
    }
}

@end
