#import <Cocoa/Cocoa.h>         // include the Cocoa Frameworks

@interface NSViewWithTopLeftCoordinateSystem : NSView
@end

@implementation NSViewWithTopLeftCoordinateSystem
- (BOOL)isFlipped {
    return YES;
}
@end

@interface LogsView : NSViewWithTopLeftCoordinateSystem
@property (retain) NSTextView* textView;
@end

@implementation LogsView
- (BOOL)isFlipped {
    return YES;
}

- (void)append:(NSString*)text {
    if (!text.length) {
        return;
    }
    NSDictionary *attrs = @{
            NSForegroundColorAttributeName: [NSColor colorWithRed:0.4 green:1.0 blue:0.4 alpha:1.0],
            NSFontAttributeName: [NSFont monospacedSystemFontOfSize:14 weight:NSFontWeightMedium]
    };
    NSAttributedString* attr = [[NSAttributedString alloc] initWithString:text attributes:attrs];
    [[self.textView textStorage] appendAttributedString:attr];
    [self.textView scrollRangeToVisible:NSMakeRange(self.textView.string.length, 0)];
    [self.textView setNeedsDisplay:YES];
}

- (void)clear {
    self.textView.string = @"";
}

- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        NSScrollView* scrollView = [NSTextView scrollableTextView];
        scrollView.frame = CGRectMake(0, 0, frame.size.width, frame.size.height);

        self.textView = scrollView.documentView;
        self.textView.textContainerInset = NSMakeSize(8, 8);
        self.textView.backgroundColor = [NSColor colorWithWhite:0.1 alpha:1.0];
        [self.textView setTextColor:[NSColor whiteColor]];
        [self.textView setEditable:NO];
        [self addSubview:scrollView];
        [self append:@"Waiting...\n"];
    }
    return self;
}
@end


@interface ContentView : NSViewWithTopLeftCoordinateSystem
@property (retain) LogsView* logsView;
@property (retain) NSTask* _Nullable ongoingTask;
@property (atomic, retain) NSMutableString* bufferedData;
- (instancetype)initWithFrame:(NSRect)frame logsView:(LogsView*)logsView;
@end

@implementation ContentView
- (instancetype)initWithFrame:(NSRect)frame logsView:(LogsView*)logsView {
    if ((self = [super initWithFrame:frame])) {
        self.logsView = logsView;
        self.bufferedData = [NSMutableString new];
        NSString* imagePath = @"/Users/philliptennen/Documents/Jailbreak/gala/assets/boot_logo_for_gui.png";
        NSImage* image = [[NSImage alloc] initByReferencingFile:imagePath];
        NSLog(@"image %@", image);
        NSImageView* logo = [NSImageView imageViewWithImage:image];

        logo.frame = NSMakeRect(
            CGRectGetWidth(frame) * 0.13,
            CGRectGetHeight(frame) * 0.1,
            CGRectGetWidth(frame) * 0.75,
            CGRectGetHeight(frame) * 0.5
        );
        NSLog(@"logo %@", NSStringFromRect(logo.frame));
        [self addSubview:logo];

        CGSize buttonSize = CGSizeMake(
            CGRectGetWidth(frame) * 0.15,
            CGRectGetHeight(frame) * 0.1
        );
        CGFloat buttonsY = CGRectGetHeight(frame) * 0.8;
        CGFloat midX = CGRectGetMidX(frame);

        NSButton* jailbreakButton = [[NSButton alloc] initWithFrame:NSMakeRect(
            midX - (buttonSize.width * 1.5),
            buttonsY,
            buttonSize.width,
            buttonSize.height
        )];
        [self addSubview:jailbreakButton];
        [jailbreakButton setTitle: @"Jailbreak"];
        [jailbreakButton setBezelStyle:NSThickerSquareBezelStyle];

        NSButton* tetheredBootButton = [[NSButton alloc] initWithFrame:NSMakeRect(
                midX + (buttonSize.width * 0.5),
                buttonsY,
                buttonSize.width,
                buttonSize.height
        )];
        [self addSubview:tetheredBootButton];
        [tetheredBootButton setTitle: @"Tethered boot"];
        [tetheredBootButton setBezelStyle:NSThickerSquareBezelStyle];

    }
    return self;
}
@end

@interface LogsView : NSViewWithTopLeftCoordinateSystem
@end

@implementation LogsView
- (BOOL)isFlipped {
    return YES;
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

@interface RunnerApp : NSObject <NSWindowDelegate>
@property (retain) NSWindow* window;
- (instancetype)init;
@end

@implementation RunnerApp
- (instancetype)init {
    if ((self = [super init])) {
        NSRect windowFrame = NSMakeRect(0, 0, 800, 500);

        NSWindowStyleMask windowStyleMask = NSWindowStyleMaskTitled
                                            |NSWindowStyleMaskClosable
                                            |NSWindowStyleMaskMiniaturizable;
        self.window = [[NSWindow alloc] initWithContentRect:windowFrame styleMask:windowStyleMask backing:NSBackingStoreBuffered defer:NO];
        [self.window center];
        self.window.title = @"gala A4 tethered iOS 4 jailbreak";

        NSViewWithTopLeftCoordinateSystem* container = [[NSViewWithTopLeftCoordinateSystem alloc] initWithFrame:windowFrame];
        NSRect controlsViewFrame = NSMakeRect(
                0,
                0,
                windowFrame.size.width,
                windowFrame.size.height * 0.6
        );

        LogsView* logsView = [[LogsView alloc] initWithFrame:NSMakeRect(
            windowFrame.origin.x,
            CGRectGetHeight(controlsViewFrame),
            windowFrame.size.width,
            CGRectGetHeight(windowFrame) - CGRectGetHeight(controlsViewFrame)
        )];
        [container addSubview:logsView];

        ContentView* controlsView = [[ContentView alloc] initWithFrame:controlsViewFrame logsView:logsView];
        [container addSubview:controlsView];

        self.window.contentView = container;
        self.window.delegate = self;
        [self.window makeKeyWindow];
        [NSApp activateIgnoringOtherApps:YES];
        [self.window orderFrontRegardless];
        [self.window makeFirstResponder:nil];
    }
    return self;
}

@end

int main(int argc, char** argv) {
    RunnerApp* app = [[RunnerApp alloc] init];
    [[NSApplication sharedApplication] run];
    return 0;
}
