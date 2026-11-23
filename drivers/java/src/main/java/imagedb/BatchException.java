package imagedb;

import java.util.Collections;
import java.util.List;

/**
 * A batch ended by an ERROR (§4): the statements (or parameter sets) before index() ran, each committed on its own
 * unless inside BEGIN ... COMMIT; their results are here; the statement at index() was undone alone; the ones after it
 * did not run.
 */
public final class BatchException extends ImagedbException {
    private static final long serialVersionUID = 1L;
    private final transient List<Result> done;

    BatchException(int code, int index, String message, List<Result> done) {
        super(code, index, message, true, null);
        this.done = Collections.unmodifiableList(done);
    }

    /** the results of the statements before the failing one, in order */
    public List<Result> completed() { return done; }
}
