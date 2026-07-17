#define TESLA_INIT_IMPL // If you have more than one file using the tesla header, only define this in the main one
#include <tesla.hpp>    // The Tesla Header
#include "ldn.h"
#include <vector>

enum class State {
    Uninit,
    Error,
    Loaded,
};

Service g_ldnSrv;
LdnMitmConfigService g_ldnConfig;
State g_state;
char g_version[32];

// Relay server picker: the ListItems, so a selection updates every marker.
std::vector<tsl::elm::ListItem*> g_serverItems;

class InternetRelayToggleListItem : public tsl::elm::ToggleListItem {
public:
    InternetRelayToggleListItem() : ToggleListItem("Internet relay", false) {
        u32 enabled = 0;
        if (R_FAILED(ldnMitmGetInternetRelay(&g_ldnConfig, &enabled))) {
            g_state = State::Error;
        }
        this->setState(enabled);

        this->setStateChangedListener([](bool enabled) {
            if (R_FAILED(ldnMitmSetInternetRelay(&g_ldnConfig, enabled))) {
                g_state = State::Error;
            }
        });
    }
};

class EnabledToggleListItem : public tsl::elm::ToggleListItem {
public:
    EnabledToggleListItem() : ToggleListItem("Enabled", false) {
        u32 enabled;
        Result rc;

        rc = ldnMitmGetEnabled(&g_ldnConfig, &enabled);
        if (R_FAILED(rc)) {
            g_state = State::Error;
        }

        this->setState(enabled);

        this->setStateChangedListener([](bool enabled) {
            Result rc = ldnMitmSetEnabled(&g_ldnConfig, enabled);
            if (R_FAILED(rc)) {
                g_state = State::Error;
            }
        });
    }
};

class LoggingToggleListItem : public tsl::elm::ToggleListItem {
public:
    LoggingToggleListItem() : ToggleListItem("Logging", false) {
        u32 enabled;
        Result rc;

        rc = ldnMitmGetLogging(&g_ldnConfig, &enabled);
        if (R_FAILED(rc)) {
            g_state = State::Error;
        }

        this->setState(enabled);

        this->setStateChangedListener([](bool enabled) {
            Result rc = ldnMitmSetLogging(&g_ldnConfig, enabled);
            if (R_FAILED(rc)) {
                g_state = State::Error;
            }
        });
    }
};

class BroadcastRelayToggleListItem : public tsl::elm::ToggleListItem {
public:
    BroadcastRelayToggleListItem() : ToggleListItem("Broadcast relay", false) {
        u32 enabled;
        Result rc;

        rc = ldnMitmGetBroadcastRelay(&g_ldnConfig, &enabled);
        if (R_FAILED(rc)) {
            g_state = State::Error;
        }

        this->setState(enabled);

        this->setStateChangedListener([](bool enabled) {
            Result rc = ldnMitmSetBroadcastRelay(&g_ldnConfig, enabled);
            if (R_FAILED(rc)) {
                g_state = State::Error;
            }
        });
    }
};

class MainGui : public tsl::Gui {
public:
    MainGui() { }

    virtual tsl::elm::Element* createUI() override {
        auto frame = new tsl::elm::OverlayFrame("ldn_mitm", g_version);

        auto list = new tsl::elm::List();

        if (g_state == State::Error) {
            list->addItem(new tsl::elm::ListItem("ldn_mitm is not loaded."));
        } else if (g_state == State::Uninit) {
            list->addItem(new tsl::elm::ListItem("wrong state"));
        } else {
            list->addItem(new EnabledToggleListItem());
            list->addItem(new BroadcastRelayToggleListItem());
            list->addItem(new LoggingToggleListItem());

            /* Internet relay: on/off toggle + a picker of the servers listed
               in /config/ldn_mitm/relay.cfg. Selecting one marks it active. */
            list->addItem(new tsl::elm::CategoryHeader("Internet relay (cross-network play)"));
            list->addItem(new InternetRelayToggleListItem());

            g_serverItems.clear();
            u32 count = 0;
            ldnMitmGetRelayServerCount(&g_ldnConfig, &count);
            if (count == 0) {
                list->addItem(new tsl::elm::ListItem("No servers - edit /config/ldn_mitm/relay.cfg"));
            } else {
                u32 selected = 0;
                ldnMitmGetSelectedRelayServer(&g_ldnConfig, &selected);
                for (u32 i = 0; i < count; i++) {
                    char name[32] = {};
                    ldnMitmGetRelayServerName(&g_ldnConfig, i, name);
                    auto *item = new tsl::elm::ListItem(name);
                    item->setValue(i == selected ? "*" : "");
                    item->setClickListener([i](u64 keys) {
                        if (keys & HidNpadButton_A) {
                            ldnMitmSetSelectedRelayServer(&g_ldnConfig, i);
                            for (size_t k = 0; k < g_serverItems.size(); k++) {
                                g_serverItems[k]->setValue(k == i ? "*" : "");
                            }
                            return true;
                        }
                        return false;
                    });
                    g_serverItems.push_back(item);
                    list->addItem(item);
                }
            }
        }

        frame->setContent(list);

        return frame;
    }

    // Called once every frame to update values
    virtual void update() override {

    }

    // Called once every frame to handle inputs not handled by other UI elements
    virtual bool handleInput(u64 keysDown, u64 keysHeld, const HidTouchState &touchPos, HidAnalogStickState joyStickPosLeft, HidAnalogStickState joyStickPosRight) {
        return false;
    }
};

class Overlay : public tsl::Overlay {
public:
    virtual void initServices() override {
        g_state = State::Uninit;
        tsl::hlp::doWithSmSession([&] {
            Result rc;

            rc = smGetService(&g_ldnSrv, "ldn:u");
            if (R_FAILED(rc)) {
                g_state = State::Error;
                return;
            }

            rc = ldnMitmGetConfigFromService(&g_ldnSrv, &g_ldnConfig);
            if (R_FAILED(rc)) {
                g_state = State::Error;
                return;
            }

            rc = ldnMitmGetVersion(&g_ldnConfig, g_version);
            if (R_FAILED(rc)) {
                strcpy(g_version, "Error");
            }

            g_state = State::Loaded;
        });

    }
    virtual void exitServices() override {
        serviceClose(&g_ldnConfig.s);
        serviceClose(&g_ldnSrv);
    }

    virtual void onShow() override {}    // Called before overlay wants to change from invisible to visible state
    virtual void onHide() override {}    // Called before overlay wants to change from visible to invisible state

    virtual std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<MainGui>();  // Initial Gui to load. It's possible to pass arguments to it's constructor like this
    }
};

int main(int argc, char **argv) {
    return tsl::loop<Overlay>(argc, argv);
}
