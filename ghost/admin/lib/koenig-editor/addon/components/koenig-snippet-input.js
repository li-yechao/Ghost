import Component from '@glimmer/component';
import getScrollParent from '../utils/get-scroll-parent';
import {TOOLBAR_MARGIN} from './koenig-toolbar';
import {action} from '@ember/object';
import {guidFor} from '@ember/object/internals';
import {run} from '@ember/runloop';
import {tracked} from '@glimmer/tracking';

// pixels that should be added to the `left` property of the tick adjustment styles
// TODO: handle via CSS?
const TICK_ADJUSTMENT = 8;

export default class KoenigSnippetInputComponent extends Component {
    @tracked name = '';
    @tracked style = ''.htmlSafe();

    constructor() {
        super(...arguments);

        // record the range now because the property is bound and will update
        // when the selection changes
        this._snippetRange = this.args.snippetRange;

        // grab a window range so that we can use getBoundingClientRect. Using
        // document.createRange is more efficient than doing editor.setRange
        // because it doesn't trigger all of the selection changing side-effects
        // TODO: extract MobiledocRange->NativeRange into a util
        let editor = this.args.editor;
        let cursor = editor.cursor;
        let {head, tail} = this.args.snippetRange;
        let {node: headNode, offset: headOffset} = cursor._findNodeForPosition(head);
        let {node: tailNode, offset: tailOffset} = cursor._findNodeForPosition(tail);
        let range = document.createRange();
        range.setStart(headNode, headOffset);
        range.setEnd(tailNode, tailOffset);
        this._windowRange = range;

        // watch the window for mousedown events so that we can close the menu
        // when we detect a click outside
        this._onMousedownHandler = run.bind(this, this._handleMousedown);
        window.addEventListener('mousedown', this._onMousedownHandler);

        // watch for keydown events so that we can close the menu on Escape
        this._onKeydownHandler = run.bind(this, this._handleKeydown);
        window.addEventListener('keydown', this._onKeydownHandler);
    }

    willDestroy() {
        window.removeEventListener('mousedown', this._onMousedownHandler);
        window.removeEventListener('keydown', this._onKeydownHandler);
        this._removeStyleElement();
    }

    @action
    focusInput(element) {
        let scrollParent = getScrollParent(element);
        let scrollTop = scrollParent.scrollTop;

        element.focus();

        // reset the scroll position to avoid jumps
        // TODO: why does the input focus cause a scroll to the bottom of the doc?
        scrollParent.scrollTop = scrollTop;
    }

    @action
    nameKeydown(event) {
        if (event.key === 'Enter') {
            // prevent Enter from triggering in the editor and removing text
            event.preventDefault();

            // convert selection into a mobiledoc document
            let {snippetRange, editor} = this.args;
            let mobiledoc = editor.serializePost(editor.post.trimTo(snippetRange), 'mobiledoc');

            this.args.save({
                name: event.target.value,
                mobiledoc
            }).then(() => {
                this.args.cancel();
            });
        }
    }

    @action
    nameInput(event) {
        this.name = event.target.value;
    }

    // TODO: largely shared with {{koenig-toolbar}} and {{koenig-link-input}} - extract to a shared util?
    @action
    registerAndPositionElement(element) {
        element.id = guidFor(element);
        this.element = element;

        let containerRect = this.element.offsetParent.getBoundingClientRect();
        let rangeRect = this.args.snippetRect || this._windowRange.getBoundingClientRect();
        let {width, height} = this.element.getBoundingClientRect();
        let newPosition = {};

        // rangeRect is relative to the viewport so we need to subtract the
        // container measurements to get a position relative to the container
        newPosition = {
            top: rangeRect.top - containerRect.top - height - TOOLBAR_MARGIN,
            left: rangeRect.left - containerRect.left + rangeRect.width / 2 - width / 2,
            right: null
        };

        let tickPosition = 50;
        // don't overflow left boundary
        if (newPosition.left < 0) {
            newPosition.left = 0;

            // calculate the tick percentage position
            let absTickPosition = rangeRect.left - containerRect.left + rangeRect.width / 2;
            tickPosition = absTickPosition / width * 100;
            if (tickPosition < 5) {
                tickPosition = 5;
            }
        }
        // same for right boundary
        if (newPosition.left + width > containerRect.width) {
            newPosition.left = null;
            newPosition.right = 0;

            // calculate the tick percentage position
            let absTickPosition = rangeRect.right - containerRect.right - rangeRect.width / 2;
            tickPosition = 100 + absTickPosition / width * 100;
            if (tickPosition > 95) {
                tickPosition = 95;
            }
        }

        // the tick is a pseudo-element so we the only way we can affect it's
        // style is by adding a style element to the head
        this._removeStyleElement(); // reset to base styles
        if (tickPosition !== 50) {
            this._addStyleElement(`left: calc(${tickPosition}% - ${TICK_ADJUSTMENT}px)`);
        }

        // update the toolbar position
        this.style = Object.keys(newPosition).map((style) => {
            if (newPosition[style] !== null) {
                return `${style}: ${newPosition[style]}px`;
            }
        }).compact().join('; ').htmlSafe();
    }

    _handleMousedown(event) {
        if (this.element && !event.target.closest(this.element.id)) {
            this.args.cancel();
        }
    }

    _handleKeydown(event) {
        if (event.key === 'Escape') {
            this._cancelAndReselect();
        }
    }

    _cancelAndReselect() {
        this.args.cancel();
        if (this._snippetRange) {
            this.args.editor.selectRange(this._snippetRange);
        }
    }

    _addStyleElement(styles) {
        let styleElement = document.createElement('style');
        styleElement.id = `${this.element.id}-style`;
        styleElement.innerHTML = `#${this.element.id}:before, #${this.element.id}:after { ${styles} }`;
        document.head.appendChild(styleElement);
    }

    _removeStyleElement() {
        let styleElement = document.querySelector(`#${this.element.id}-style`);
        if (styleElement) {
            styleElement.remove();
        }
    }
}
