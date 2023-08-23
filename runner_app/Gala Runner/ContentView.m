//
//  ContentView.m
//  Gala Runner
//
//  Created by Phillip Tennen on 19/08/2023.
//

#import "ContentView.h"

@implementation ContentView

- (instancetype)initWithFrame:(NSRect)frame logsView:(LogsView*)logsView {
    if ((self = [super initWithFrame:frame])) {
        self.logsView = logsView;
        self.bufferedData = [NSMutableString new];
        //NSString* imagePath = @"/Users/philliptennen/Documents/Jailbreak/gala/assets/boot_logo_for_gui.png";
        //NSString* imagePath = @"/Users/philliptennen/Documents/Jailbreak/gala/assets/boot_logo_for_gui.png";
        //NSImage* image = [[NSImage alloc] initByReferencingFile:imagePath];
        NSImage* image = [NSImage imageNamed:@"boot_logo_for_gui.png"];
        NSImageView* logo = [NSImageView imageViewWithImage:image];

        logo.frame = NSMakeRect(
            CGRectGetWidth(frame) * 0.13,
            CGRectGetHeight(frame) * 0.1,
            CGRectGetWidth(frame) * 0.75,
            CGRectGetHeight(frame) * 0.5
        );
        [self addSubview:logo];

        CGSize buttonSize = CGSizeMake(
            CGRectGetWidth(frame) * 0.15,
            CGRectGetHeight(frame) * 0.1
        );
        CGFloat buttonsY = CGRectGetHeight(frame) * 0.85;
        CGFloat midX = CGRectGetMidX(frame);

        NSButton* jailbreakButton = [[NSButton alloc] initWithFrame:NSMakeRect(
            midX - (buttonSize.width * 1.5),
            buttonsY,
            buttonSize.width,
            buttonSize.height
        )];
        [self addSubview:jailbreakButton];
        [jailbreakButton setTitle: @"Jailbreak"];
        [jailbreakButton setBezelStyle:NSBezelStyleRegularSquare];
        jailbreakButton.target = self;
        jailbreakButton.action = @selector(jailbreakButtonClicked:);

        NSButton* tetheredBootButton = [[NSButton alloc] initWithFrame:NSMakeRect(
                midX + (buttonSize.width * 0.5),
                buttonsY,
                buttonSize.width,
                buttonSize.height
        )];
        [self addSubview:tetheredBootButton];
        [tetheredBootButton setTitle: @"Tethered boot"];
        [tetheredBootButton setBezelStyle:NSBezelStyleRegularSquare];
        tetheredBootButton.target = self;
        tetheredBootButton.action = @selector(bootButtonClicked:);

        self.statusLabel = [[NSTextView alloc] initWithFrame:NSMakeRect(
            0,
            frame.size.height * 0.7,
            frame.size.width,
            frame.size.height * 0.1
        )];
        self.statusLabel.editable = NO;
        self.statusLabel.string = @"Ready!";
        self.statusLabel.alignment = NSTextAlignmentCenter;
        self.statusLabel.font = [NSFont monospacedSystemFontOfSize:18 weight:NSFontWeightBold];
        self.statusLabel.backgroundColor = [NSColor clearColor];
        [self addSubview:self.statusLabel];
    }
    return self;
}

- (void)jailbreakButtonClicked:(NSButton*)sender {
    // TODO(PT): Check if there's an ongoing task and clear all our buffers
    [self.logsView clear];
    [self runGala:@[@"--jailbreak"]];
}

- (void)bootButtonClicked:(NSButton*)sender {
    [self.logsView clear];
    [self runGala:@[@"--boot"]];
}

- (void)runGala:(NSArray<NSString*>*)args {
    // TODO(PT): Ensure there's no ongoing task
    self.ongoingTask = [[NSTask alloc] init];
    //self.ongoingTask.executableURL = [NSURL fileURLWithPath:@"/Users/philliptennen/.pyenv/versions/3.11.1/envs/jailbreak/bin/python"].absoluteURL;
    // Invoke bash instead of Python directly so that the Python script spawned by gala pick up the PATH
    self.ongoingTask.executableURL = [NSURL fileURLWithPath:@"/bin/bash"];
    
    char c_event_log_file[] = "/tmp/gala-event-log-XXXXXX";
    int event_log_fd = mkstemp(c_event_log_file);
    if (event_log_fd == -1) {
        NSLog(@"Failed to make event log file?!");
        exit(1);
    }
    // TODO(PT): Delete the event log file once gala exits
    NSString* eventLogFilePath = [NSString stringWithUTF8String:c_event_log_file];
    //NSFileHandle* eventLogHandle = [NSFileHandle fileHandleForReadingAtPath:eventLogFilePath];
    self.eventLogHandle = [[NSFileHandle alloc] initWithFileDescriptor:event_log_fd];
    // Update the status label when new data becomes available on the event log
    __weak typeof(self) weakSelf = self;
    self.eventLogHandle.readabilityHandler = ^(NSFileHandle* handle){
        NSData* eventBytes = handle.availableData;
        NSString* event = [[NSString alloc] initWithBytes:eventBytes.bytes length:eventBytes.length encoding:NSUTF8StringEncoding];
        dispatch_async(dispatch_get_main_queue(), ^{
            weakSelf.statusLabel.string = event;
        });
    };

    NSArray* extendedGalaArgs = [args arrayByAddingObject:[NSString stringWithFormat:@"--log_high_level_events_to_file %@", eventLogFilePath]];
    NSString* galaArgsAsStr = [extendedGalaArgs componentsJoinedByString:@" "];
    
    NSMutableArray* arguments = [NSMutableArray arrayWithArray:@[
        @"-l",
        @"-c",
        // -u for unbuffered stdout
        [NSString stringWithFormat:@"/Users/philliptennen/.pyenv/versions/3.11.1/envs/jailbreak/bin/python -u /Users/philliptennen/Documents/Jailbreak/gala/jailbreak.py %@", galaArgsAsStr],
    ]];
    self.ongoingTask.arguments = arguments;

    NSPipe* stdoutPipe = [NSPipe pipe];
    [self.ongoingTask setStandardOutput:stdoutPipe];
    [self.ongoingTask setStandardError:stdoutPipe];

    stdoutPipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle* handle){
        NSData* outputBytes = handle.availableData;
        NSString* output = [[NSString alloc] initWithBytes:outputBytes.bytes length:outputBytes.length encoding:NSUTF8StringEncoding];
        [self.bufferedData appendString:output];
    };
    
    [self.ongoingTask launch];
    [self flushAvailableOutput];
}

- (void)flushAvailableOutput {
    [self.logsView append:self.bufferedData];
    self.bufferedData = [NSMutableString new];

    CGFloat refreshInterval = 0.2;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, refreshInterval * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [self flushAvailableOutput];
    });
}

@end
