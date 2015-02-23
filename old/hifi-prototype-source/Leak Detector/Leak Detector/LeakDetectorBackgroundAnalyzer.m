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
@property (atomic, strong) NSTask *realTimeTask;
-(NSDictionary*)parseJSON:(NSData*)json;
@end

@implementation LeakDetectorBackgroundAnalyzer
@synthesize listeners = _listeners;
@synthesize realTimeTask = _realTimeTask;
-(NSMutableSet*)listeners {
    if (!_listeners) {
        _listeners = [[NSMutableSet alloc]initWithCapacity:5];
    }
    return _listeners;
}

@synthesize infoDelegate = _infoDelegate;



#pragma mark Analyze Real Time

-(void) analyzeRealTimeHelper:(NSTask*)task {
    NSString *BASE_PATH = @"/Users/dnaylor/Documents/School/CMU/leak-detector";
    
    [task setLaunchPath: @"/usr/bin/python"];
    
    NSArray *arguments;
    arguments = [NSArray arrayWithObjects:@"-u", [BASE_PATH stringByAppendingPathComponent:@"leakdetector.py"], @"-G", @"5", nil];
    [task setArguments: arguments];
    
    NSPipe *pipe;
    pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    NSFileHandle *file;
    file = [pipe fileHandleForReading];
    
    [task launch];
    
    NSData *data;
    data = [file availableData];
    while (data && [task isRunning]) {
        
        //NSString* dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        //NSLog(@"DATA CHUNK:\n$%@\n\n", dataStr);
        
        NSDictionary* info_dict = [self parseJSON:data];
        if (info_dict) {
            dispatch_queue_t q_main = dispatch_get_main_queue();
            dispatch_async(q_main, ^{
                [self.infoDelegate updateLeakInfo:info_dict];
            });            
        }
        
        
        data = [file availableData];
    }
}


-(void) startAnalyzeRealTime {
    if (self.realTimeTask) {
        return;  // If we're already sniffing, don't start a new process
    }
    
    self.realTimeTask = [[NSTask alloc] init];
    
    dispatch_queue_t q_default = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_async(q_default, ^{
        
        [self analyzeRealTimeHelper:self.realTimeTask];
        
    });
    [self notifyListenersStartedWithMessage:@"Analyzing current network traffic..."];
}

-(void) stopAnalyzeRealTime {
    [self.realTimeTask terminate];
    self.realTimeTask = nil;
    [self notifyListenersFinished];
}




#pragma mark Analyze Trace

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
    
    return [self parseJSON:data];
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
    [self notifyListenersStartedWithMessage:@"Analyzing packet trace..."];
}



#pragma mark Helper Methods

-(NSDictionary*)parseJSON:(NSData *)json {
    NSError *error = nil;
    NSDictionary *info_dict = [NSJSONSerialization JSONObjectWithData:json options:0 error:&error];
    if (error) {
        NSLog(@"Error parsing JSON");
        return nil;
    } else {
        return info_dict;
    }
}

-(void) addActivityListener:(id<AnalyzerActivityListener>)listener {
    [self.listeners addObject:listener];
}

-(void) removeActivityListener:(id<AnalyzerActivityListener>)listener {
    [self.listeners removeObject:listener];  // TODO: check that listener is in set?
}

-(void) notifyListenersStartedWithMessage:(NSString*)message {
    for (id<AnalyzerActivityListener> listener in self.listeners) {
        [listener analyzerDidStart:self withMessage:message];
    }
}

-(void) notifyListenersFinished {
    for (id<AnalyzerActivityListener> listener in self.listeners) {
        [listener analyzerDidFinish:self];
    }
}

@end
